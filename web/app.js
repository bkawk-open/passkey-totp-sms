(function () {
    'use strict';

    const API = 'https://api.totp-sms.bkawk.com';
    const {
        startRegistration,
        browserSupportsWebAuthn,
    } = SimpleWebAuthnBrowser;

    // -- State machine --
    const State = {
        BOOT: 'BOOT',
        IDLE: 'IDLE',
        CHECKING: 'CHECKING',
        OTP_SENT: 'OTP_SENT',
        REGISTERING: 'REGISTERING',
        AUTHENTICATING: 'AUTHENTICATING',
        VERIFYING: 'VERIFYING',
        DONE: 'DONE',
        ERROR: 'ERROR',
        INVITING: 'INVITING',
        ACCEPTING_INVITE: 'ACCEPTING_INVITE',
    };

    let currentState = State.BOOT;
    let autofillAbort = null;
    let masterKey = null;
    let prfSupported = false;
    let pendingOtpId = null;
    let pendingPhone = null;
    let pendingCountryCode = null;
    const PRF_SALT = new TextEncoder().encode('passkey-prf-note-v1').buffer;

    const $auth = document.getElementById('authView');
    const $otpView = document.getElementById('otpView');
    const $verify = document.getElementById('verifyingView');
    const $logged = document.getElementById('loggedInView');
    const $phone = document.getElementById('phone');
    const $countryCode = document.getElementById('countryCode');
    const $btn = document.getElementById('continueBtn');
    const $status = document.getElementById('status');
    const $loggedPhone = document.getElementById('loggedInPhone');
    const $passkeySection = document.getElementById('passkeySection');
    const $noteSection = document.getElementById('noteSection');
    const $logoutBtn = document.getElementById('logoutBtn');
    const $otpCode = document.getElementById('otpCode');
    const $verifyOtpBtn = document.getElementById('verifyOtpBtn');
    const $resendOtpBtn = document.getElementById('resendOtpBtn');
    const $otpStatus = document.getElementById('otpStatus');

    // -- Base64url helpers --
    function b64urlToBuffer(str) {
        let s = str.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        const bin = atob(s);
        const buf = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
        return buf.buffer;
    }

    function bufferToB64url(buf) {
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (const b of bytes) bin += String.fromCharCode(b);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // -- Envelope encryption crypto helpers --

    async function deriveWrappingKey(prfOutput) {
        var keyMaterial = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new TextEncoder().encode('passkey-crossdevice-prf-wrapping'),
                info: new TextEncoder().encode('aes-kw-256'),
            },
            keyMaterial,
            { name: 'AES-KW', length: 256 },
            false,
            ['wrapKey', 'unwrapKey']
        );
    }

    async function generateMasterKey() {
        return crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    async function wrapMasterKey(wrappingKey, mk) {
        var wrapped = await crypto.subtle.wrapKey('raw', mk, wrappingKey, 'AES-KW');
        return bufferToB64url(wrapped);
    }

    async function unwrapMasterKey(wrappingKey, wrappedB64) {
        var wrapped = b64urlToBuffer(wrappedB64);
        return crypto.subtle.unwrapKey(
            'raw', wrapped, wrappingKey, 'AES-KW',
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    async function encryptNote(key, plaintext) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encoded
        );
        return {
            ciphertext: bufferToB64url(ciphertext),
            iv: bufferToB64url(iv),
        };
    }

    async function decryptNote(key, ciphertextB64, ivB64) {
        const ciphertext = b64urlToBuffer(ciphertextB64);
        const iv = b64urlToBuffer(ivB64);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    }

    // -- Invite crypto helpers --

    async function encryptMasterKeyForInvite(mk, inviteSecretBytes) {
        var aesKey = await crypto.subtle.importKey(
            'raw', inviteSecretBytes, { name: 'AES-GCM' }, false, ['encrypt']
        );
        var iv = crypto.getRandomValues(new Uint8Array(12));
        var rawKey = await crypto.subtle.exportKey('raw', mk);
        var ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            aesKey,
            rawKey
        );
        var combined = new Uint8Array(12 + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), 12);
        return bufferToB64url(combined.buffer);
    }

    async function decryptMasterKeyFromInvite(encryptedB64, inviteSecretBytes) {
        var combined = new Uint8Array(b64urlToBuffer(encryptedB64));
        var iv = combined.slice(0, 12);
        var ciphertext = combined.slice(12);
        var aesKey = await crypto.subtle.importKey(
            'raw', inviteSecretBytes, { name: 'AES-GCM' }, false, ['decrypt']
        );
        var rawKey = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            aesKey,
            ciphertext
        );
        return crypto.subtle.importKey(
            'raw', rawKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
    }

    function fadeOutForm() {
        return new Promise(resolve => {
            $auth.classList.add('fade-out');
            $auth.addEventListener('transitionend', resolve, { once: true });
            setTimeout(resolve, 250);
        });
    }

    function setState(newState, ctx) {
        ctx = ctx || {};
        currentState = newState;
        $auth.classList.add('hidden');
        $auth.classList.remove('fade-out');
        $otpView.classList.add('hidden');
        $verify.classList.add('hidden');
        $logged.classList.add('hidden');
        $status.textContent = '';
        $status.className = '';

        // Remove invite overlay if present
        var existingOverlay = document.querySelector('.invite-overlay');
        if (existingOverlay && newState !== State.INVITING && newState !== State.DONE) {
            existingOverlay.remove();
        }

        // Remove accept invite view if present
        var existingAccept = document.querySelector('.invite-accept');
        if (existingAccept && newState !== State.ACCEPTING_INVITE) {
            existingAccept.remove();
        }

        switch (newState) {
            case State.BOOT:
            case State.REGISTERING:
            case State.AUTHENTICATING:
            case State.VERIFYING:
                $verify.classList.remove('hidden');
                break;
            case State.IDLE:
                $auth.classList.remove('hidden');
                $btn.disabled = false;
                $btn.textContent = 'Continue';
                break;
            case State.CHECKING:
                $auth.classList.remove('hidden');
                $btn.disabled = true;
                $btn.textContent = 'Checking...';
                break;
            case State.OTP_SENT:
                $otpView.classList.remove('hidden');
                $otpCode.value = '';
                $otpCode.focus();
                $verifyOtpBtn.disabled = false;
                $verifyOtpBtn.textContent = 'Verify';
                $otpStatus.textContent = '';
                $otpStatus.className = '';
                break;
            case State.DONE:
                $logged.classList.remove('hidden');
                if (ctx.phone) $loggedPhone.textContent = ctx.phone;
                renderPasskeySection();
                renderNoteSection();
                break;
            case State.ERROR:
                $auth.classList.remove('hidden');
                $btn.disabled = false;
                $btn.textContent = 'Continue';
                if (ctx.message) {
                    $status.textContent = ctx.message;
                    $status.className = 'error';
                }
                break;
            case State.ACCEPTING_INVITE:
                // Handled by showAcceptInviteUI
                break;
        }
    }

    // -- Passkey management UI --

    function renderPasskeySection() {
        $passkeySection.textContent = '';

        var heading = document.createElement('h2');
        heading.textContent = 'Passkeys';

        var listContainer = document.createElement('div');
        listContainer.className = 'passkey-list';
        listContainer.id = 'passkeyList';

        var btnRow = document.createElement('div');
        btnRow.className = 'passkey-btn-row';

        var addBtn = document.createElement('button');
        addBtn.className = 'btn-primary';
        addBtn.textContent = 'Add Passkey';
        addBtn.addEventListener('click', handleAddPasskey);
        btnRow.appendChild(addBtn);

        if (masterKey) {
            var linkBtn = document.createElement('button');
            linkBtn.className = 'btn-primary';
            linkBtn.textContent = 'Link New Device';
            linkBtn.addEventListener('click', handleLinkNewDevice);
            btnRow.appendChild(linkBtn);
        }

        var statusDiv = document.createElement('div');
        statusDiv.id = 'passkeyStatus';
        statusDiv.className = 'passkey-status';

        $passkeySection.appendChild(heading);
        $passkeySection.appendChild(listContainer);
        $passkeySection.appendChild(btnRow);
        $passkeySection.appendChild(statusDiv);

        loadPasskeys();
    }

    async function loadPasskeys() {
        var token = localStorage.getItem('passkey_token');
        var $list = document.getElementById('passkeyList');
        try {
            var data = await api('/passkeys', {
                method: 'GET',
                headers: { Authorization: 'Bearer ' + token },
            });
            $list.textContent = '';
            var passkeys = data.passkeys || [];
            for (var i = 0; i < passkeys.length; i++) {
                var pk = passkeys[i];
                var item = document.createElement('div');
                item.className = 'passkey-item';

                var info = document.createElement('div');
                info.className = 'passkey-item-info';

                var idEl = document.createElement('div');
                idEl.className = 'passkey-id';
                idEl.textContent = pk.deviceInfo || pk.credentialId.substring(0, 16) + '...';

                var dateEl = document.createElement('div');
                dateEl.className = 'passkey-date';
                if (pk.createdAt) {
                    var d = new Date(pk.createdAt);
                    dateEl.textContent = 'Added ' + d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
                        + ' at ' + d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
                }

                info.appendChild(idEl);
                info.appendChild(dateEl);

                var actions = document.createElement('div');
                actions.className = 'passkey-actions';

                if (!pk.hasWrappedKey && masterKey) {
                    var verifyBtn = document.createElement('button');
                    verifyBtn.className = 'btn-verify-sm';
                    verifyBtn.textContent = 'Verify';
                    verifyBtn.setAttribute('data-cred-id', pk.credentialId);
                    verifyBtn.addEventListener('click', function () {
                        handleVerifyPasskey(this.getAttribute('data-cred-id'));
                    });
                    actions.appendChild(verifyBtn);
                }

                var delBtn = document.createElement('button');
                delBtn.className = 'btn-danger-sm';
                delBtn.textContent = 'Delete';
                delBtn.disabled = passkeys.length <= 1;
                delBtn.setAttribute('data-cred-id', pk.credentialId);
                delBtn.addEventListener('click', function () {
                    handleDeletePasskey(this.getAttribute('data-cred-id'));
                });
                actions.appendChild(delBtn);

                item.appendChild(info);
                item.appendChild(actions);
                $list.appendChild(item);
            }
        } catch (e) {
            console.error('Failed to load passkeys:', e);
        }
    }

    async function handleDeletePasskey(credentialId) {
        if (!confirm('Delete this passkey? You will no longer be able to log in with it.')) return;
        var token = localStorage.getItem('passkey_token');
        var $ps = document.getElementById('passkeyStatus');
        try {
            $ps.textContent = 'Deleting...';
            await api('/passkeys', {
                method: 'DELETE',
                headers: { Authorization: 'Bearer ' + token },
                body: JSON.stringify({ credentialId: credentialId }),
            });
            $ps.textContent = '';
            loadPasskeys();
        } catch (e) {
            console.error('Failed to delete passkey:', e);
            $ps.textContent = 'Delete failed. Try again.';
        }
    }

    async function handleAddPasskey() {
        var token = localStorage.getItem('passkey_token');
        var $ps = document.getElementById('passkeyStatus');
        try {
            $ps.textContent = 'Creating passkey...';

            var beginResp = await api('/passkeys/add/begin', {
                method: 'POST',
                headers: { Authorization: 'Bearer ' + token },
            });

            var cred = await startRegistration({
                optionsJSON: Object.assign({}, beginResp.options.publicKey, {
                    extensions: Object.assign({}, beginResp.options.publicKey.extensions, { prf: {} }),
                }),
            });

            await api('/passkeys/add/finish', {
                method: 'POST',
                headers: { Authorization: 'Bearer ' + token },
                body: JSON.stringify({ challengeID: beginResp.challengeID, credential: cred }),
            });

            $ps.textContent = 'Passkey added. Click Verify to link it for encrypted notes.';
            loadPasskeys();
        } catch (e) {
            console.error('Failed to add passkey:', e);
            if (e.name === 'NotAllowedError') {
                $ps.textContent = 'Passkey creation was cancelled.';
            } else if (e.name === 'InvalidStateError') {
                $ps.textContent = 'This device already has a passkey for this account.';
            } else {
                $ps.textContent = 'Failed to add passkey. Try again.';
            }
        }
    }

    async function handleVerifyPasskey(credentialId) {
        var token = localStorage.getItem('passkey_token');
        var $ps = document.getElementById('passkeyStatus');
        try {
            $ps.textContent = 'Verifying passkey...';

            var credIdBuffer = b64urlToBuffer(credentialId);

            var loginResp = await api('/login/begin', { method: 'POST' });
            var pk = loginResp.options.publicKey;
            pk.challenge = b64urlToBuffer(pk.challenge);
            pk.allowCredentials = [{ id: credIdBuffer, type: 'public-key' }];
            pk.extensions = { prf: { eval: { first: PRF_SALT } } };

            var assertion = await navigator.credentials.get({ publicKey: pk });

            var extResults = assertion.getClientExtensionResults();
            var prfResult = extResults && extResults.prf && extResults.prf.results && extResults.prf.results.first;

            var credential = {
                id: assertion.id,
                rawId: bufferToB64url(assertion.rawId),
                type: assertion.type,
                response: {
                    authenticatorData: bufferToB64url(assertion.response.authenticatorData),
                    clientDataJSON: bufferToB64url(assertion.response.clientDataJSON),
                    signature: bufferToB64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToB64url(assertion.response.userHandle) : undefined,
                },
                clientExtensionResults: extResults,
                authenticatorAttachment: assertion.authenticatorAttachment,
            };
            var loginResult = await api('/login/finish', {
                method: 'POST',
                body: JSON.stringify({ challengeID: loginResp.challengeID, credential: credential }),
            });

            if (loginResult.token) {
                api('/logout', {
                    method: 'POST',
                    headers: { Authorization: 'Bearer ' + loginResult.token },
                }).catch(function () {});
            }

            if (loginResult.credentialId !== credentialId) {
                $ps.textContent = 'Credential mismatch. Please try again.';
                loadPasskeys();
                return;
            }

            if (!prfResult) {
                $ps.textContent = 'PRF not supported by this passkey. Notes won\'t decrypt with it.';
                loadPasskeys();
                return;
            }

            var newWrappingKey = await deriveWrappingKey(prfResult);
            var wrappedB64 = await wrapMasterKey(newWrappingKey, masterKey);

            await api('/passkeys/wrapped-key', {
                method: 'PUT',
                headers: { Authorization: 'Bearer ' + token },
                body: JSON.stringify({ credentialId: credentialId, wrappedKey: wrappedB64 }),
            });

            $ps.textContent = 'Passkey verified and linked.';
            loadPasskeys();
        } catch (e) {
            console.error('Failed to verify passkey:', e);
            if (e.name === 'NotAllowedError') {
                $ps.textContent = 'Verification was cancelled.';
            } else {
                $ps.textContent = 'Verification failed. Try again.';
            }
        }
    }

    // -- Device A: Link New Device flow --

    var invitePollTimer = null;
    var inviteCountdownTimer = null;

    async function handleLinkNewDevice() {
        if (!masterKey) return;
        var token = localStorage.getItem('passkey_token');
        var $ps = document.getElementById('passkeyStatus');
        try {
            $ps.textContent = 'Creating invite...';

            var inviteSecretBytes = crypto.getRandomValues(new Uint8Array(32));
            var encryptedMK = await encryptMasterKeyForInvite(masterKey, inviteSecretBytes);

            var resp = await api('/invite/create', {
                method: 'POST',
                headers: { Authorization: 'Bearer ' + token },
                body: JSON.stringify({ encryptedMasterKey: encryptedMK }),
            });

            var inviteId = resp.inviteId;
            var inviteSecretB64 = bufferToB64url(inviteSecretBytes.buffer);
            var inviteUrl = location.origin + '/?invite=' + inviteId + '#' + inviteSecretB64;

            $ps.textContent = '';
            showInviteModal(inviteId, inviteUrl, token);
        } catch (e) {
            console.error('Failed to create invite:', e);
            $ps.textContent = e.message === 'too many active invites' ?
                'Too many active invites. Wait for them to expire.' :
                'Failed to create invite. Try again.';
        }
    }

    function showInviteModal(inviteId, inviteUrl, token) {
        // Remove existing overlay
        var existing = document.querySelector('.invite-overlay');
        if (existing) existing.remove();

        var overlay = document.createElement('div');
        overlay.className = 'invite-overlay';

        var modal = document.createElement('div');
        modal.className = 'invite-modal';

        var title = document.createElement('h2');
        title.textContent = 'Link New Device';

        var qrContainer = document.createElement('div');
        qrContainer.className = 'invite-qr';

        // Generate QR code
        var qr = qrcode(0, 'M');
        qr.addData(inviteUrl);
        qr.make();
        var canvas = document.createElement('canvas');
        var cellSize = 4;
        var moduleCount = qr.getModuleCount();
        var margin = 16;
        canvas.width = moduleCount * cellSize + margin * 2;
        canvas.height = moduleCount * cellSize + margin * 2;
        var ctx2d = canvas.getContext('2d');
        ctx2d.fillStyle = '#ffffff';
        ctx2d.fillRect(0, 0, canvas.width, canvas.height);
        ctx2d.fillStyle = '#000000';
        for (var r = 0; r < moduleCount; r++) {
            for (var c = 0; c < moduleCount; c++) {
                if (qr.isDark(r, c)) {
                    ctx2d.fillRect(margin + c * cellSize, margin + r * cellSize, cellSize, cellSize);
                }
            }
        }
        qrContainer.appendChild(canvas);

        var countdown = document.createElement('div');
        countdown.className = 'invite-countdown';
        countdown.id = 'inviteCountdown';

        var statusEl = document.createElement('div');
        statusEl.className = 'invite-status';
        statusEl.id = 'inviteStatus';
        statusEl.textContent = 'Waiting for device to scan...';

        var cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn-secondary';
        cancelBtn.textContent = 'Cancel';
        cancelBtn.addEventListener('click', function () {
            clearInterval(invitePollTimer);
            clearInterval(inviteCountdownTimer);
            invitePollTimer = null;
            inviteCountdownTimer = null;
            overlay.remove();
        });

        modal.appendChild(title);
        modal.appendChild(qrContainer);
        modal.appendChild(countdown);
        modal.appendChild(statusEl);
        modal.appendChild(cancelBtn);
        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        // Start 5-minute countdown
        var endTime = Date.now() + 5 * 60 * 1000;
        function updateCountdown() {
            var remaining = Math.max(0, endTime - Date.now());
            var mins = Math.floor(remaining / 60000);
            var secs = Math.floor((remaining % 60000) / 1000);
            var $cd = document.getElementById('inviteCountdown');
            if ($cd) $cd.textContent = mins + ':' + (secs < 10 ? '0' : '') + secs;
            if (remaining <= 0) {
                clearInterval(inviteCountdownTimer);
                clearInterval(invitePollTimer);
                var $is = document.getElementById('inviteStatus');
                if ($is) $is.textContent = 'Expired';
            }
        }
        updateCountdown();
        inviteCountdownTimer = setInterval(updateCountdown, 1000);

        // Poll for status
        invitePollTimer = setInterval(async function () {
            try {
                var data = await api('/invite/status?inviteId=' + encodeURIComponent(inviteId), {
                    method: 'GET',
                    headers: { Authorization: 'Bearer ' + token },
                });
                var $is = document.getElementById('inviteStatus');
                if (!$is) return;

                if (data.expired) {
                    $is.textContent = 'Expired';
                    clearInterval(invitePollTimer);
                    clearInterval(inviteCountdownTimer);
                    return;
                }

                if (data.status === 'registered') {
                    $is.textContent = 'Device registered, completing link...';
                }

                if (data.status === 'completed') {
                    $is.textContent = 'Linked!';
                    clearInterval(invitePollTimer);
                    clearInterval(inviteCountdownTimer);
                    setTimeout(function () {
                        overlay.remove();
                        loadPasskeys();
                    }, 2000);
                }
            } catch (e) {
                console.error('Poll error:', e);
            }
        }, 3000);
    }

    // -- Device B: Accept invite flow --

    async function handleAcceptInvite(inviteId, inviteSecretB64) {
        var inviteSecretBytes = new Uint8Array(b64urlToBuffer(inviteSecretB64));

        try {
            var info = await api('/invite/info?inviteId=' + encodeURIComponent(inviteId), {
                method: 'GET',
            });

            if (info.status !== 'pending') {
                setState(State.ERROR, { message: 'This invite link has already been used.' });
                cleanInviteUrl();
                return;
            }

            showAcceptInviteUI(info.phone, inviteId, inviteSecretBytes);
        } catch (e) {
            console.error('Invite info error:', e);
            setState(State.ERROR, { message: 'Invalid or expired invite link.' });
            cleanInviteUrl();
        }
    }

    function showAcceptInviteUI(maskedPhone, inviteId, inviteSecretBytes) {
        currentState = State.ACCEPTING_INVITE;

        // Hide all standard views
        $auth.classList.add('hidden');
        $otpView.classList.add('hidden');
        $verify.classList.add('hidden');
        $logged.classList.add('hidden');

        var container = document.querySelector('.container');

        var view = document.createElement('div');
        view.className = 'invite-accept';

        var title = document.createElement('h2');
        title.textContent = 'Link Passkey';

        var phoneEl = document.createElement('p');
        phoneEl.className = 'invite-accept-email';
        phoneEl.textContent = 'Account: ' + maskedPhone;

        var desc = document.createElement('p');
        desc.className = 'invite-accept-desc';
        desc.textContent = 'Create a passkey on this device to link it to the account above.';

        var createBtn = document.createElement('button');
        createBtn.className = 'btn-primary';
        createBtn.textContent = 'Create Passkey';

        var statusEl = document.createElement('div');
        statusEl.className = 'invite-accept-status';
        statusEl.id = 'inviteAcceptStatus';

        createBtn.addEventListener('click', async function () {
            createBtn.disabled = true;
            createBtn.textContent = 'Creating...';
            statusEl.textContent = '';

            try {
                // Step 1: Register begin
                statusEl.textContent = 'Starting registration...';
                var beginResp = await api('/invite/register/begin', {
                    method: 'POST',
                    body: JSON.stringify({ inviteId: inviteId }),
                });

                // Step 2: startRegistration (biometric #1)
                statusEl.textContent = 'Create your passkey...';
                var cred = await startRegistration({
                    optionsJSON: beginResp.options.publicKey,
                });

                // Step 3: Register finish
                statusEl.textContent = 'Verifying credential...';
                var finishResp = await api('/invite/register/finish', {
                    method: 'POST',
                    body: JSON.stringify({
                        inviteId: inviteId,
                        challengeID: beginResp.challengeID,
                        credential: cred,
                    }),
                });

                // Step 4: Decrypt master key from invite
                statusEl.textContent = 'Decrypting master key...';
                var decryptedMK = await decryptMasterKeyFromInvite(
                    finishResp.encryptedMasterKey, inviteSecretBytes
                );

                // Store the token from invite registration
                localStorage.setItem('passkey_token', finishResp.token);

                // Step 5: Login ceremony targeting new credential + PRF eval (biometric #2)
                statusEl.textContent = 'Authenticate passkey to complete link...';

                var credIdBuffer = b64urlToBuffer(finishResp.credentialId);
                var loginResp = await api('/login/begin', { method: 'POST' });
                var pk = loginResp.options.publicKey;
                pk.challenge = b64urlToBuffer(pk.challenge);
                pk.allowCredentials = [{ id: credIdBuffer, type: 'public-key' }];
                pk.extensions = { prf: { eval: { first: PRF_SALT } } };

                var assertion = await navigator.credentials.get({ publicKey: pk });

                var extResults = assertion.getClientExtensionResults();
                var prfResult = extResults && extResults.prf && extResults.prf.results && extResults.prf.results.first;

                var credential = {
                    id: assertion.id,
                    rawId: bufferToB64url(assertion.rawId),
                    type: assertion.type,
                    response: {
                        authenticatorData: bufferToB64url(assertion.response.authenticatorData),
                        clientDataJSON: bufferToB64url(assertion.response.clientDataJSON),
                        signature: bufferToB64url(assertion.response.signature),
                        userHandle: assertion.response.userHandle ? bufferToB64url(assertion.response.userHandle) : undefined,
                    },
                    clientExtensionResults: extResults,
                    authenticatorAttachment: assertion.authenticatorAttachment,
                };

                var loginResult = await api('/login/finish', {
                    method: 'POST',
                    body: JSON.stringify({ challengeID: loginResp.challengeID, credential: credential }),
                });

                // Step 6: Logout orphaned verify token
                if (loginResult.token) {
                    api('/logout', {
                        method: 'POST',
                        headers: { Authorization: 'Bearer ' + loginResult.token },
                    }).catch(function () {});
                }

                if (!prfResult) {
                    statusEl.textContent = 'PRF not supported. Cannot complete link.';
                    return;
                }

                // Step 7: Derive wrapping key, wrap masterKey
                statusEl.textContent = 'Storing encrypted key...';
                var wrappingKey = await deriveWrappingKey(prfResult);
                var wrappedB64 = await wrapMasterKey(wrappingKey, decryptedMK);

                var authToken = localStorage.getItem('passkey_token');
                await api('/passkeys/wrapped-key', {
                    method: 'PUT',
                    headers: { Authorization: 'Bearer ' + authToken },
                    body: JSON.stringify({
                        credentialId: finishResp.credentialId,
                        wrappedKey: wrappedB64,
                    }),
                });

                // Step 8: Complete invite
                await api('/invite/complete', {
                    method: 'POST',
                    headers: { Authorization: 'Bearer ' + authToken },
                    body: JSON.stringify({ inviteId: inviteId }),
                });

                // Success — transition to logged-in state
                masterKey = decryptedMK;
                cleanInviteUrl();

                // Remove the accept UI
                view.remove();
                setState(State.DONE, { phone: finishResp.phone });

            } catch (e) {
                console.error('Accept invite error:', e);
                createBtn.disabled = false;
                createBtn.textContent = 'Create Passkey';
                if (e.name === 'NotAllowedError') {
                    statusEl.textContent = 'Passkey creation was cancelled. Try again.';
                } else if (e.message === 'invite already used') {
                    statusEl.textContent = 'This invite has already been used.';
                } else {
                    statusEl.textContent = 'Failed: ' + e.message;
                }
            }
        });

        view.appendChild(title);
        view.appendChild(phoneEl);
        view.appendChild(desc);
        view.appendChild(createBtn);
        view.appendChild(statusEl);
        container.appendChild(view);
    }

    function cleanInviteUrl() {
        var url = new URL(location.href);
        url.searchParams.delete('invite');
        url.hash = '';
        history.replaceState(null, '', url.pathname);
    }

    // -- Re-authenticate to unlock notes --
    async function handleReauth() {
        var $rs = document.getElementById('reauthStatus');
        try {
            $rs.textContent = 'Authenticating...';

            var resp = await api('/login/begin', { method: 'POST' });
            var pk = resp.options.publicKey;
            pk.challenge = b64urlToBuffer(pk.challenge);
            if (pk.allowCredentials) {
                for (var i = 0; i < pk.allowCredentials.length; i++) {
                    var ac = pk.allowCredentials[i];
                    if (typeof ac.id === 'string') ac.id = b64urlToBuffer(ac.id);
                }
            }
            pk.extensions = Object.assign({}, pk.extensions, { prf: { eval: { first: PRF_SALT } } });

            var assertion = await navigator.credentials.get({ publicKey: pk });

            var extResults = assertion.getClientExtensionResults();
            var prfResult = extResults && extResults.prf && extResults.prf.results && extResults.prf.results.first;

            var credential = {
                id: assertion.id,
                rawId: bufferToB64url(assertion.rawId),
                type: assertion.type,
                response: {
                    authenticatorData: bufferToB64url(assertion.response.authenticatorData),
                    clientDataJSON: bufferToB64url(assertion.response.clientDataJSON),
                    signature: bufferToB64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToB64url(assertion.response.userHandle) : undefined,
                },
                clientExtensionResults: extResults,
                authenticatorAttachment: assertion.authenticatorAttachment,
            };

            var result = await api('/login/finish', {
                method: 'POST',
                body: JSON.stringify({ challengeID: resp.challengeID, credential: credential }),
            });

            if (result.token) {
                api('/logout', {
                    method: 'POST',
                    headers: { Authorization: 'Bearer ' + result.token },
                }).catch(function () {});
            }

            if (!prfResult || !result.credentialId) {
                $rs.textContent = 'PRF not available. Notes cannot be decrypted.';
                return;
            }

            var wrappingKey = await deriveWrappingKey(prfResult);
            var token = localStorage.getItem('passkey_token');
            var wkData = await api('/passkeys/wrapped-key?credentialId=' + encodeURIComponent(result.credentialId), {
                method: 'GET',
                headers: { Authorization: 'Bearer ' + token },
            });

            if (wkData.exists) {
                masterKey = await unwrapMasterKey(wrappingKey, wkData.wrappedKey);
            } else {
                masterKey = await generateMasterKey();
                var wrappedB64 = await wrapMasterKey(wrappingKey, masterKey);
                await api('/passkeys/wrapped-key', {
                    method: 'PUT',
                    headers: { Authorization: 'Bearer ' + token },
                    body: JSON.stringify({ credentialId: result.credentialId, wrappedKey: wrappedB64 }),
                });
            }

            renderPasskeySection();
            renderNoteSection();
        } catch (e) {
            if (e.name === 'NotAllowedError') {
                $rs.textContent = '';
            } else {
                console.error('Re-auth failed:', e);
                $rs.textContent = 'Authentication failed. Try again.';
            }
        }
    }

    // -- Note UI --
    function renderNoteSection() {
        $noteSection.textContent = '';

        if (!masterKey) {
            var hint = document.createElement('div');
            hint.className = 'note-hint';
            hint.textContent = 'Re-authenticate with your passkey to access encrypted notes.';
            $noteSection.appendChild(hint);

            var reauthBtn = document.createElement('button');
            reauthBtn.className = 'btn-primary';
            reauthBtn.textContent = 'Unlock Notes';
            reauthBtn.addEventListener('click', handleReauth);
            $noteSection.appendChild(reauthBtn);

            var reauthStatus = document.createElement('div');
            reauthStatus.id = 'reauthStatus';
            reauthStatus.className = 'note-status';
            $noteSection.appendChild(reauthStatus);
            return;
        }

        var textarea = document.createElement('textarea');
        textarea.id = 'noteText';
        textarea.placeholder = 'Write your secret note here...';

        var saveBtn = document.createElement('button');
        saveBtn.className = 'btn-primary';
        saveBtn.textContent = 'Save Note';
        saveBtn.addEventListener('click', saveNote);

        var statusDiv = document.createElement('div');
        statusDiv.id = 'noteStatus';
        statusDiv.className = 'note-status';

        $noteSection.appendChild(textarea);
        $noteSection.appendChild(saveBtn);
        $noteSection.appendChild(statusDiv);

        loadNote();
    }

    async function loadNote() {
        if (!masterKey) return;
        var token = localStorage.getItem('passkey_token');
        try {
            var data = await api('/note', {
                method: 'GET',
                headers: { Authorization: 'Bearer ' + token },
            });
            if (data.exists) {
                var plaintext = await decryptNote(masterKey, data.ciphertext, data.iv);
                var $note = document.getElementById('noteText');
                if ($note) $note.value = plaintext;
                var $ns = document.getElementById('noteStatus');
                if ($ns && data.updatedAt) $ns.textContent = 'Last saved: ' + new Date(data.updatedAt).toLocaleString();
            }
        } catch (e) {
            console.error('Failed to load note:', e);
        }
    }

    async function saveNote() {
        if (!masterKey) return;
        var $note = document.getElementById('noteText');
        var $ns = document.getElementById('noteStatus');
        var token = localStorage.getItem('passkey_token');
        try {
            $ns.textContent = 'Saving...';
            var encrypted = await encryptNote(masterKey, $note.value);
            await api('/note', {
                method: 'PUT',
                headers: { Authorization: 'Bearer ' + token },
                body: JSON.stringify({ ciphertext: encrypted.ciphertext, iv: encrypted.iv }),
            });
            $ns.textContent = 'Last saved: ' + new Date().toLocaleString();
        } catch (e) {
            console.error('Failed to save note:', e);
            $ns.textContent = 'Save failed. Try again.';
        }
    }

    // -- API helper --
    async function api(path, opts) {
        opts = opts || {};
        var res = await fetch(API + path, {
            headers: Object.assign({ 'Content-Type': 'application/json' }, opts.headers),
            method: opts.method,
            body: opts.body,
        });
        var data = await res.json();
        if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
        return data;
    }

    // -- Session check --
    async function checkSession() {
        var token = localStorage.getItem('passkey_token');
        if (!token) return false;
        try {
            var data = await api('/session', {
                method: 'GET',
                headers: { Authorization: 'Bearer ' + token },
            });
            if (data.authenticated) {
                setState(State.DONE, { phone: data.phone });
                return true;
            }
        } catch (e) {
            localStorage.removeItem('passkey_token');
        }
        return false;
    }

    // -- Envelope encryption login helper --
    async function handleEnvelopeLogin(wrappingKey, credentialId) {
        var token = localStorage.getItem('passkey_token');
        var wkData = await api('/passkeys/wrapped-key?credentialId=' + encodeURIComponent(credentialId), {
            method: 'GET',
            headers: { Authorization: 'Bearer ' + token },
        });

        if (wkData.exists) {
            masterKey = await unwrapMasterKey(wrappingKey, wkData.wrappedKey);
        } else {
            masterKey = await generateMasterKey();
            var wrappedB64 = await wrapMasterKey(wrappingKey, masterKey);
            await api('/passkeys/wrapped-key', {
                method: 'PUT',
                headers: { Authorization: 'Bearer ' + token },
                body: JSON.stringify({ credentialId: credentialId, wrappedKey: wrappedB64 }),
            });
        }
    }

    // -- Autofill flow (uses direct WebAuthn API for proper abort + PRF) --
    async function startAutofillFlow() {
        try {
            var resp = await api('/login/begin', { method: 'POST' });
            var challengeID = resp.challengeID;
            var options = resp.options;

            if (currentState !== State.IDLE && currentState !== State.BOOT) return;

            var pk = options.publicKey;
            pk.challenge = b64urlToBuffer(pk.challenge);
            if (pk.allowCredentials) {
                for (var i = 0; i < pk.allowCredentials.length; i++) {
                    var ac = pk.allowCredentials[i];
                    if (typeof ac.id === 'string') ac.id = b64urlToBuffer(ac.id);
                }
            }

            pk.extensions = Object.assign({}, pk.extensions, { prf: { eval: { first: PRF_SALT } } });

            autofillAbort = new AbortController();
            var assertion = await navigator.credentials.get({
                publicKey: pk,
                mediation: 'conditional',
                signal: autofillAbort.signal,
            });
            autofillAbort = null;

            var extResults = assertion.getClientExtensionResults();
            var prfResult = extResults && extResults.prf && extResults.prf.results && extResults.prf.results.first;
            var wrappingKey = null;
            if (prfResult) {
                wrappingKey = await deriveWrappingKey(prfResult);
            }

            var credential = {
                id: assertion.id,
                rawId: bufferToB64url(assertion.rawId),
                type: assertion.type,
                response: {
                    authenticatorData: bufferToB64url(assertion.response.authenticatorData),
                    clientDataJSON: bufferToB64url(assertion.response.clientDataJSON),
                    signature: bufferToB64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToB64url(assertion.response.userHandle) : undefined,
                },
                clientExtensionResults: extResults,
                authenticatorAttachment: assertion.authenticatorAttachment,
            };

            setState(State.VERIFYING);
            var result = await api('/login/finish', {
                method: 'POST',
                body: JSON.stringify({ challengeID: challengeID, credential: credential }),
            });

            localStorage.setItem('passkey_token', result.token);

            if (wrappingKey && result.credentialId) {
                await handleEnvelopeLogin(wrappingKey, result.credentialId);
            } else {
                masterKey = null;
            }

            setState(State.DONE, { phone: result.phone });
        } catch (e) {
            autofillAbort = null;
            if (e.name === 'AbortError') return;
            console.log('Autofill not available:', e.message);
        }
    }

    function handleError(e) {
        if (e.name === 'NotAllowedError') {
            setState(State.IDLE);
            return;
        }
        if (e.name === 'InvalidStateError') {
            setState(State.ERROR, { message: 'This device already has a passkey. Try signing in.' });
            return;
        }
        if (e.message === 'Failed to fetch' || e.name === 'TypeError') {
            setState(State.ERROR, { message: 'Connection issue. Please try again.' });
            return;
        }
        if (e.message === 'invalid phone number') {
            setState(State.ERROR, { message: 'Enter a valid phone number.' });
            return;
        }
        console.error('Passkey error:', e);
        setState(State.ERROR, { message: 'Something went wrong. Please try again.' });
    }

    // -- PRF login via direct WebAuthn API --
    async function loginWithPRF(challengeID, options) {
        var pk = options.publicKey;

        pk.challenge = b64urlToBuffer(pk.challenge);

        if (pk.allowCredentials) {
            for (var i = 0; i < pk.allowCredentials.length; i++) {
                var ac = pk.allowCredentials[i];
                if (typeof ac.id === 'string') ac.id = b64urlToBuffer(ac.id);
            }
        }

        pk.extensions = Object.assign({}, pk.extensions, { prf: { eval: { first: PRF_SALT } } });

        var assertion = await navigator.credentials.get({ publicKey: pk });

        var extResults = assertion.getClientExtensionResults();
        var prfResult = extResults && extResults.prf && extResults.prf.results && extResults.prf.results.first;
        var wrappingKey = null;
        if (prfResult) {
            wrappingKey = await deriveWrappingKey(prfResult);
        }

        var credential = {
            id: assertion.id,
            rawId: bufferToB64url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToB64url(assertion.response.authenticatorData),
                clientDataJSON: bufferToB64url(assertion.response.clientDataJSON),
                signature: bufferToB64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bufferToB64url(assertion.response.userHandle) : undefined,
            },
            clientExtensionResults: extResults,
            authenticatorAttachment: assertion.authenticatorAttachment,
        };

        setState(State.VERIFYING);
        var result = await api('/login/finish', {
            method: 'POST',
            body: JSON.stringify({ challengeID: challengeID, credential: credential }),
        });

        localStorage.setItem('passkey_token', result.token);

        if (wrappingKey && result.credentialId) {
            await handleEnvelopeLogin(wrappingKey, result.credentialId);
        } else {
            masterKey = null;
        }

        setState(State.DONE, { phone: result.phone });
    }

    // -- OTP verification --
    async function handleOTPVerify() {
        var code = $otpCode.value.trim();
        if (code.length !== 6 || !/^\d{6}$/.test(code)) {
            $otpStatus.textContent = 'Enter a 6-digit code.';
            $otpStatus.className = 'error';
            return;
        }

        $verifyOtpBtn.disabled = true;
        $verifyOtpBtn.textContent = 'Verifying...';
        $otpStatus.textContent = '';
        $otpStatus.className = '';

        try {
            var resp = await api('/auth/verify-otp', {
                method: 'POST',
                body: JSON.stringify({ otpId: pendingOtpId, code: code }),
            });

            if (resp.action === 'register') {
                setState(State.REGISTERING);
                var cred = await startRegistration({
                    optionsJSON: Object.assign({}, resp.options.publicKey, {
                        extensions: Object.assign({}, resp.options.publicKey.extensions, { prf: {} }),
                    }),
                });
                prfSupported = !!(cred.clientExtensionResults && cred.clientExtensionResults.prf && cred.clientExtensionResults.prf.enabled);
                masterKey = null;
                setState(State.VERIFYING);
                var result = await api('/register/finish', {
                    method: 'POST',
                    body: JSON.stringify({ challengeID: resp.challengeID, credential: cred }),
                });
                localStorage.setItem('passkey_token', result.token);
                setState(State.DONE, { phone: result.phone });
            }
        } catch (e) {
            if (e.name === 'NotAllowedError') {
                setState(State.IDLE);
                return;
            }
            $verifyOtpBtn.disabled = false;
            $verifyOtpBtn.textContent = 'Verify';
            $otpStatus.textContent = e.message || 'Verification failed. Try again.';
            $otpStatus.className = 'error';
        }
    }

    async function handleResendOTP() {
        $otpStatus.textContent = 'Resending...';
        $otpStatus.className = '';
        try {
            var resp = await api('/auth/begin', {
                method: 'POST',
                body: JSON.stringify({ phone: pendingPhone, countryCode: pendingCountryCode }),
            });
            if (resp.action === 'otp_required') {
                pendingOtpId = resp.otpId;
                $otpStatus.textContent = 'Code resent.';
            }
        } catch (e) {
            $otpStatus.textContent = e.message || 'Failed to resend. Try again.';
            $otpStatus.className = 'error';
        }
    }

    // -- Continue button --
    async function handleContinue() {
        var phone = $phone.value.trim();
        if (!phone) {
            setState(State.ERROR, { message: 'Enter your phone number.' });
            return;
        }

        var countryCode = $countryCode.value;

        if (autofillAbort) {
            autofillAbort.abort();
            autofillAbort = null;
        }

        setState(State.CHECKING);

        try {
            var resp = await api('/auth/begin', {
                method: 'POST',
                body: JSON.stringify({ phone: phone, countryCode: countryCode }),
            });
            var action = resp.action;

            if (action === 'otp_required') {
                // New user — show OTP input
                pendingOtpId = resp.otpId;
                pendingPhone = phone;
                pendingCountryCode = countryCode;
                setState(State.OTP_SENT);
                return;
            }

            var challengeID = resp.challengeID;
            var options = resp.options;

            await fadeOutForm();

            if (action === 'login') {
                setState(State.AUTHENTICATING);
                await loginWithPRF(challengeID, options);
            }
        } catch (e) {
            handleError(e);
        }
    }

    // -- Logout --
    async function handleLogout() {
        var token = localStorage.getItem('passkey_token');
        if (token) {
            try {
                await api('/logout', {
                    method: 'POST',
                    headers: { Authorization: 'Bearer ' + token },
                });
            } catch (e) {
                // Continue with local cleanup even if server logout fails
            }
        }
        localStorage.removeItem('passkey_token');
        masterKey = null;
        prfSupported = false;
        pendingOtpId = null;
        pendingPhone = null;
        pendingCountryCode = null;
        setState(State.IDLE);
        startAutofillFlow();
    }

    // -- Event listeners (no inline handlers) --
    $btn.addEventListener('click', handleContinue);
    $logoutBtn.addEventListener('click', handleLogout);
    $verifyOtpBtn.addEventListener('click', handleOTPVerify);
    $resendOtpBtn.addEventListener('click', handleResendOTP);

    // -- Boot sequence --
    (async function () {
        setState(State.BOOT);

        if (!browserSupportsWebAuthn()) {
            setState(State.ERROR, { message: 'Your browser does not support passkeys.' });
            $btn.disabled = true;
            return;
        }

        // Check for invite link: ?invite=<id>#<secret>
        var urlParams = new URLSearchParams(location.search);
        var inviteId = urlParams.get('invite');
        if (inviteId && location.hash.length > 1) {
            var inviteSecretB64 = location.hash.substring(1);
            await handleAcceptInvite(inviteId, inviteSecretB64);
            return;
        }

        if (await checkSession()) return;

        setState(State.IDLE);
        startAutofillFlow();
    })();
})();
