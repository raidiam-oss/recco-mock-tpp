(function(){
    const rawParams = location.hash ? location.hash.slice(1) : (location.search.startsWith('?') ? location.search.slice(1) : '');
    const qp = new URLSearchParams(rawParams);

    const code = qp.get('code') || '';
    const state = qp.get('state') || '';

    const providerSel = document.getElementById('providerSel');
    const resultBox = document.getElementById('resultBox');
    const idTokenBox = document.getElementById('idTokenBox');
    const introspectBox = document.getElementById('introspectBox');
    const btnCopyId = document.getElementById('copyId');
    const btnCopyIntro = document.getElementById('copyIntro');

    function show(json, isError=false){
        // force status field to be shown first when present
        let ordered = json;
        if (json && typeof json === 'object' && !Array.isArray(json) && Object.prototype.hasOwnProperty.call(json, 'status')) {
            const rest = Object.fromEntries(Object.entries(json).filter(([k]) => k !== 'status'));
            ordered = { status: json.status, ...rest }
        }

        resultBox.classList.toggle('error', !!isError);
        resultBox.textContent = JSON.stringify(ordered, null, 2);
    }

    async function exchangeTokenIfNeeded(){
        if(!code || !state) return;
        const res = await fetch('/auth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ code, state })
        });
        const data = await res.json();

        if(!res.ok){
            show(data || { error: 'token exchange failed' }, true);
            return;
        }

        if (data.id_token_payload) {
            idTokenBox.textContent = JSON.stringify(data.id_token_payload, null, 2);
        } else if (data.id_token_error) {
            idTokenBox.textContent = JSON.stringify({ error: data.id_token_error }, null, 2);
        } else {
            idTokenBox.textContent = JSON.stringify({ note: 'no ID token data available' }, null, 2);
        }

        if (data.introspection) {
            introspectBox.textContent = JSON.stringify(data.introspection, null, 2);
        } else if (data.introspection_error) {
            introspectBox.textContent = JSON.stringify({ error: data.introspection_error }, null, 2);
        } else {
            introspectBox.textContent = JSON.stringify({ note: 'no introspection payload' }, null, 2);
        }
    }

    async function loadProviders(){
        const res = await fetch('/providers', { credentials: 'include' });
        const list = await res.json();
        providerSel.innerHTML = '';
        list.forEach(p => providerSel.add(new Option(p.CustomerFriendlyName, p.AuthorisationServerId)));
    }

    async function run(endpoint){
        const providerId = providerSel.value;
        resultBox.textContent = 'Loading...';

        try {
            // Make the API call to the TPP service (same origin)
            const res = await fetch(`/api/${endpoint}?provider_id=${encodeURIComponent(providerId)}`, {
                credentials: 'include'
            });
            const data = await res.json().catch(()=> ({}));
            show(data, !res.ok);
        } catch (error) {
            show({ error: error.message }, true);
        }
    }

    document.getElementById('btnCustomer').addEventListener('click',()=>run('customer'));
    document.getElementById('btnEnergy').addEventListener('click',()=>run('energy'));

    btnCopyId.addEventListener('click', () => {
        if (navigator.clipboard) navigator.clipboard.writeText((idTokenBox.textContent || '').trim());
    });

    btnCopyIntro.addEventListener('click', () => {
        if (navigator.clipboard) navigator.clipboard.writeText((introspectBox.textContent || '').trim());
    });

    (async function init(){
        await exchangeTokenIfNeeded();
        await loadProviders();
        if (providerSel.options.length) run('customer');
    })();
})();
