(function(){
    const scopesBox = document.getElementById('scopesBox');
    const scopeCell = document.getElementById('p_scope');
    const pResponseType = document.getElementById('p_response_type')
    const pClientId = document.getElementById('p_client_id');
    const pRedirect = document.getElementById('p_redirect_uri');
    const pCCMethod = document.getElementById('p_cc_method');
    const pChallenge = document.getElementById('p_code_challenge');
    const pState = document.getElementById('p_state');
    const pNonce = document.getElementById('p_nonce')
    const btnCopyScopes = document.getElementById('copyScopes');
    const btnCopyUrl = document.getElementById('copyUrl');
    const btnAuthorize = document.getElementById('authorizeBtn');

    let latestAuthURL = '';

    function scopesFromOptions(){
        const scopes = ['openid'];
        if(document.getElementById('opt-customer').checked) scopes.push('customer');
        if(document.getElementById('opt-energy').checked) scopes.push('energy');
        return scopes;
    }

    function renderScopes(){
        const scopes = scopesFromOptions();
        scopesBox.textContent = JSON.stringify(scopes, null, 2);
        scopeCell.textContent = scopes.join(' ');
    }

    async function buildAuth(){
        const scopes = scopesFromOptions();
        const res = await fetch('/auth/build', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ scopes })
        });
        const data = await res.json();

        pResponseType.textContent = data.response_type || 'code';
        pClientId.textContent = data.client_id || '—';
        pRedirect.textContent = data.redirect_uri || '—';
        pCCMethod.textContent = data.code_challenge_method || 'S256';
        pChallenge.textContent = data.code_challenge || '—';
        pState.textContent = data.state || '—';
        pNonce.textContent = data.nonce || '—'

        latestAuthURL = '';
    }

    async function ensureFinalizedURL(){
        if (latestAuthURL) return latestAuthURL;
        const res = await fetch('/auth/finalize', {
            method: 'POST',
            credentials: 'include'
        });
        const data = await res.json();
        latestAuthURL = data.auth_url || '';
        return latestAuthURL;
    }

    btnCopyScopes.addEventListener('click',()=>{
        navigator.clipboard && navigator.clipboard.writeText(scopesBox.textContent);
    });

    btnCopyUrl.addEventListener('click', async ()=>{
        const url = await ensureFinalizedURL();
        if(navigator.clipboard && url) navigator.clipboard.writeText(url);
    });

    btnAuthorize.addEventListener('click', async ()=>{
        const url = await ensureFinalizedURL();
        if (url) location.href = url;
    });

    document.querySelectorAll('#opt-customer,#opt-energy').forEach(el=>{
        el.addEventListener('change', async ()=>{
            renderScopes();
            await buildAuth();
        });
    });

    renderScopes();
    buildAuth();
})();
