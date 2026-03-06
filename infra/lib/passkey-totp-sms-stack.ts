import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as apigwv2Integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { GoFunction } from '@aws-cdk/aws-lambda-go-alpha';
import { Construct } from 'constructs';
import * as path from 'path';

export class PasskeyTotpSmsStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // --- DNS Zone ---

    const hostedZone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
      hostedZoneId: 'Z0965730BW5PZCFXVDVF',
      zoneName: 'bkawk.com',
    });

    // --- Certificate (DNS-validated for totp-sms.bkawk.com + api.totp-sms.bkawk.com) ---

    const certificate = new acm.Certificate(this, 'Certificate', {
      domainName: 'totp-sms.bkawk.com',
      subjectAlternativeNames: ['api.totp-sms.bkawk.com'],
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // --- DynamoDB ---

    const table = new dynamodb.Table(this, 'Table', {
      tableName: 'passkey-totp-sms',
      partitionKey: { name: 'PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'SK', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'TTL',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    table.addGlobalSecondaryIndex({
      indexName: 'UserID-index',
      partitionKey: { name: 'UserID', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // --- Lambda (Go) ---

    const lambdaFn = new GoFunction(this, 'ApiFunction', {
      functionName: 'passkey-totp-sms-api',
      entry: path.join(__dirname, '../../api'),
      runtime: cdk.aws_lambda.Runtime.PROVIDED_AL2023,
      architecture: cdk.aws_lambda.Architecture.X86_64,
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        DYNAMODB_TABLE: table.tableName,
        SMS_REGION: 'eu-west-2',
      },
      bundling: {
        goBuildFlags: ['-tags lambda.norpc'],
        cgoEnabled: false,
      },
    });

    table.grantReadWriteData(lambdaFn);

    // IAM policy for SNS SMS
    lambdaFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['sns:Publish'],
      resources: ['*'],
    }));

    // --- CloudWatch Alarms ---

    new cloudwatch.Alarm(this, 'LambdaErrorAlarm', {
      metric: lambdaFn.metricErrors({
        period: cdk.Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 10,
      evaluationPeriods: 1,
      alarmDescription: 'Lambda error rate exceeds 10 errors in 5 minutes',
    });

    new cloudwatch.Alarm(this, 'LambdaThrottleAlarm', {
      metric: lambdaFn.metricThrottles({
        period: cdk.Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 5,
      evaluationPeriods: 1,
      alarmDescription: 'Lambda throttles exceed 5 in 5 minutes',
    });

    // --- API Gateway HTTP API ---

    const lambdaIntegration = new apigwv2Integrations.HttpLambdaIntegration(
      'LambdaIntegration', lambdaFn,
    );

    const httpApi = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: 'passkey-totp-sms-api',
      createDefaultStage: false,
    });

    const routes: Array<{ path: string; method: apigwv2.HttpMethod }> = [
      { path: '/auth/begin', method: apigwv2.HttpMethod.POST },
      { path: '/auth/verify-otp', method: apigwv2.HttpMethod.POST },
      { path: '/register/finish', method: apigwv2.HttpMethod.POST },
      { path: '/login/begin', method: apigwv2.HttpMethod.POST },
      { path: '/login/finish', method: apigwv2.HttpMethod.POST },
      { path: '/session', method: apigwv2.HttpMethod.GET },
      { path: '/logout', method: apigwv2.HttpMethod.POST },
      { path: '/note', method: apigwv2.HttpMethod.GET },
      { path: '/note', method: apigwv2.HttpMethod.PUT },
      { path: '/passkeys', method: apigwv2.HttpMethod.GET },
      { path: '/passkeys/add/begin', method: apigwv2.HttpMethod.POST },
      { path: '/passkeys/add/finish', method: apigwv2.HttpMethod.POST },
      { path: '/passkeys', method: apigwv2.HttpMethod.DELETE },
      { path: '/passkeys/wrapped-key', method: apigwv2.HttpMethod.PUT },
      { path: '/passkeys/wrapped-key', method: apigwv2.HttpMethod.GET },
      { path: '/invite/create', method: apigwv2.HttpMethod.POST },
      { path: '/invite/info', method: apigwv2.HttpMethod.GET },
      { path: '/invite/register/begin', method: apigwv2.HttpMethod.POST },
      { path: '/invite/register/finish', method: apigwv2.HttpMethod.POST },
      { path: '/invite/status', method: apigwv2.HttpMethod.GET },
      { path: '/invite/complete', method: apigwv2.HttpMethod.POST },
    ];

    for (const route of routes) {
      httpApi.addRoutes({
        path: route.path,
        methods: [route.method],
        integration: lambdaIntegration,
      });
    }

    // OPTIONS routes for CORS preflight (handled by Lambda)
    const optionsPaths = [...new Set(routes.map(r => r.path))];
    for (const routePath of optionsPaths) {
      httpApi.addRoutes({
        path: routePath,
        methods: [apigwv2.HttpMethod.OPTIONS],
        integration: lambdaIntegration,
      });
    }

    const stage = new apigwv2.HttpStage(this, 'DefaultStage', {
      httpApi,
      stageName: '$default',
      autoDeploy: true,
      throttle: {
        rateLimit: 100,
        burstLimit: 200,
      },
    });

    // Custom domain for API Gateway
    const apiDomainName = new apigwv2.DomainName(this, 'ApiDomainName', {
      domainName: 'api.totp-sms.bkawk.com',
      certificate,
    });

    new apigwv2.ApiMapping(this, 'ApiMapping', {
      api: httpApi,
      domainName: apiDomainName,
      stage,
    });

    // Route53 A record for API
    new route53.ARecord(this, 'ApiAliasRecord', {
      zone: hostedZone,
      recordName: 'api.totp-sms',
      target: route53.RecordTarget.fromAlias(
        new targets.ApiGatewayv2DomainProperties(
          apiDomainName.regionalDomainName,
          apiDomainName.regionalHostedZoneId,
        ),
      ),
    });

    // --- S3 Bucket (frontend) ---

    const websiteBucket = new s3.Bucket(this, 'WebsiteBucket', {
      bucketName: 'totp-sms-bkawk-com',
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // --- WAF ---

    const waf = new wafv2.CfnWebACL(this, 'WebAcl', {
      defaultAction: { allow: {} },
      scope: 'CLOUDFRONT',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'passkey-totp-sms-waf',
        sampledRequestsEnabled: true,
      },
      rules: [
        {
          name: 'AWSManagedRulesCommonRuleSet',
          priority: 1,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'common-rules',
            sampledRequestsEnabled: true,
          },
        },
        {
          name: 'AWSManagedRulesKnownBadInputsRuleSet',
          priority: 2,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesKnownBadInputsRuleSet',
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'known-bad-inputs',
            sampledRequestsEnabled: true,
          },
        },
        {
          name: 'RateLimitPerIP',
          priority: 3,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              limit: 1000,
              aggregateKeyType: 'IP',
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'rate-limit-per-ip',
            sampledRequestsEnabled: true,
          },
        },
      ],
    });

    // --- CloudFront ---

    const responseHeadersPolicy = new cloudfront.ResponseHeadersPolicy(this, 'SecurityHeaders', {
      securityHeadersBehavior: {
        contentSecurityPolicy: {
          contentSecurityPolicy: "default-src 'none'; script-src 'self'; style-src 'self'; connect-src https://api.totp-sms.bkawk.com; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
          override: true,
        },
        strictTransportSecurity: {
          accessControlMaxAge: cdk.Duration.seconds(63072000),
          includeSubdomains: true,
          override: true,
        },
        contentTypeOptions: { override: true },
        referrerPolicy: {
          referrerPolicy: cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
          override: true,
        },
        frameOptions: {
          frameOption: cloudfront.HeadersFrameOption.DENY,
          override: true,
        },
      },
    });

    const distribution = new cloudfront.Distribution(this, 'Distribution', {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(websiteBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy,
      },
      domainNames: ['totp-sms.bkawk.com'],
      certificate,
      defaultRootObject: 'index.html',
      webAclId: waf.attrArn,
    });

    // Route53 A record for CloudFront
    new route53.ARecord(this, 'CloudFrontAliasRecord', {
      zone: hostedZone,
      recordName: 'totp-sms',
      target: route53.RecordTarget.fromAlias(
        new targets.CloudFrontTarget(distribution),
      ),
    });

    // --- S3 Deployment ---

    new s3deploy.BucketDeployment(this, 'DeployWebsite', {
      sources: [s3deploy.Source.asset(path.join(__dirname, '../../web'))],
      destinationBucket: websiteBucket,
      distribution,
      distributionPaths: ['/*'],
    });

    // --- Outputs ---

    new cdk.CfnOutput(this, 'ApiUrl', {
      value: `https://api.totp-sms.bkawk.com`,
    });

    new cdk.CfnOutput(this, 'WebUrl', {
      value: `https://totp-sms.bkawk.com`,
    });

    new cdk.CfnOutput(this, 'HttpApiEndpoint', {
      value: httpApi.apiEndpoint,
    });
  }
}
