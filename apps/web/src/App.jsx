import { useEffect, useState } from 'react';

const fetchJson = async (url) => {
  const response = await fetch(url, { headers: { Accept: 'application/json' } });
  const body = await response.json();
  return { ok: response.ok, status: response.status, body };
};

export default function App() {
  const [health, setHealth] = useState({ loading: true, data: null, error: null });

  useEffect(() => {
    let active = true;

    fetchJson('/smoke')
      .then((result) => {
        if (!active) {
          return;
        }
        setHealth({ loading: false, data: result, error: null });
      })
      .catch((error) => {
        if (!active) {
          return;
        }
        setHealth({ loading: false, data: null, error: error.message });
      });

    return () => {
      active = false;
    };
  }, []);

  return (
    <main style={{ fontFamily: 'Inter, system-ui, sans-serif', padding: 24 }}>
      <h1>Neweast Bootstrap</h1>
      <p>React + Vite 前端骨架已就绪。</p>
      {health.loading && <p>正在执行最小 smoke 探测...</p>}
      {!health.loading && health.error && <p>smoke 失败：{health.error}</p>}
      {!health.loading && health.data && (
        <pre style={{ background: '#f6f8fa', padding: 16, borderRadius: 8, overflowX: 'auto' }}>
          {JSON.stringify(health.data, null, 2)}
        </pre>
      )}
    </main>
  );
}
