#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { PasskeyTotpSmsStack } from '../lib/passkey-totp-sms-stack';

const app = new cdk.App();
new PasskeyTotpSmsStack(app, 'PasskeyTotpSmsStack', {
  env: {
    account: '238576302016',
    region: 'us-east-1',
  },
});
