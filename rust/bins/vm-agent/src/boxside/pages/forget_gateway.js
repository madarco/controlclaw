
  try {
    const KEY = 'controlclaw.install';
    if (d.install && localStorage.getItem(KEY) !== d.install) {
      localStorage.clear(); sessionStorage.clear();
      if (indexedDB.databases) {
        const dbs = await indexedDB.databases();
        await Promise.all(dbs.filter((x) => x.name).map((x) => new Promise((done) => {
          const req = indexedDB.deleteDatabase(x.name); req.onsuccess = req.onerror = req.onblocked = () => done();
        })));
      }
      localStorage.setItem(KEY, d.install);
    }
  } catch (e) { /* storage blocked: the bootstrap link still works in a clean browser */ }