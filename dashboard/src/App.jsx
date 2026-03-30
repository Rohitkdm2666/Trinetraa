import { useEffect, useState, useRef, useCallback } from "react";
import axios from "axios";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, BarChart, Bar
} from "recharts";

const API    = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws";
const COLORS = ["#ff3864","#ff9f0a","#30d158","#0a84ff","#bf5af2","#ff6b35","#00d4ff"];

const ATTACK_ICONS = {
  "DDoS": "⚡", "PortScan": "🔍", "DoS Hulk": "💥",
  "DoS GoldenEye": "👁", "Bot": "🤖", "Infiltration": "🕵️",
  "Heartbleed": "🩸", "FTP-Patator": "🔓", "SSH-Patator": "🔐",
  "Web Attack  Brute Force": "🪓", "Web Attack  Sql Injection": "💉",
  "Web Attack  XSS": "☠️", "default": "🚨"
};

const getRiskColor = (s) => s >= 80 ? "#ff3864" : s >= 50 ? "#ff9f0a" : s >= 30 ? "#0a84ff" : "#30d158";
const getRiskLabel = (s) => s >= 80 ? "CRITICAL" : s >= 50 ? "HIGH" : s >= 30 ? "MEDIUM" : "LOW";

function Counter({ value }) {
  const [display, setDisplay] = useState(0);
  const prev = useRef(0);
  useEffect(() => {
    const diff = value - prev.current;
    if (!diff) return;
    let i = 0;
    const t = setInterval(() => {
      i++;
      setDisplay(Math.round(prev.current + diff * i / 20));
      if (i >= 20) { clearInterval(t); prev.current = value; }
    }, 30);
    return () => clearInterval(t);
  }, [value]);
  return <span>{display.toLocaleString()}</span>;
}

function PulseDot({ color = "#30d158" }) {
  return (
    <span style={{ position:"relative", display:"inline-block", width:10, height:10 }}>
      <span style={{ position:"absolute", inset:0, borderRadius:"50%", background:color, animation:"pulse 1.5s ease-in-out infinite" }} />
      <span style={{ position:"absolute", inset:2, borderRadius:"50%", background:color }} />
    </span>
  );
}

function ThreatBar({ score }) {
  const color = getRiskColor(score);
  return (
    <div style={{ display:"flex", alignItems:"center", gap:8 }}>
      <div style={{ flex:1, height:6, background:"#1c2333", borderRadius:3, overflow:"hidden" }}>
        <div style={{ width:`${score}%`, height:"100%", background:color, borderRadius:3, transition:"width 0.8s ease", boxShadow:`0 0 8px ${color}` }} />
      </div>
      <span style={{ color, fontSize:11, fontWeight:700, fontFamily:"monospace", minWidth:32 }}>{score}</span>
    </div>
  );
}

export default function App() {
  const [stats, setStats]       = useState({ total_flows:0, total_attacks:0, benign:0, attack_counts:{}, blocked_ips:[], high_risk_ips:[] });
  const [alerts, setAlerts]     = useState([]);
  const [defense, setDefense]   = useState({ high_risk_ips:[] });
  const [history, setHistory]   = useState([]);
  const [tab, setTab]           = useState("overview");
  const [loading, setLoading]   = useState(true);
  const [wsStatus, setWsStatus] = useState("connecting"); // connecting | live | offline
  const [newAlert, setNewAlert] = useState(false);
  const wsRef = useRef(null);

  const fetchAll = useCallback(async () => {
    try {
      const [s, a, d] = await Promise.all([
        axios.get(`${API}/stats`),
        axios.get(`${API}/alerts?limit=30`),
        axios.get(`${API}/defense`),
      ]);
      setStats(s.data);
      setAlerts(a.data);
      setDefense(d.data);
      setHistory(prev => [...prev.slice(-20), {
        time: new Date().toLocaleTimeString("en", { hour12:false, hour:"2-digit", minute:"2-digit", second:"2-digit" }),
        flows:   s.data.total_flows,
        attacks: s.data.total_attacks,
      }]);
    } catch (e) {
      console.error("API error:", e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // ── WebSocket setup ──
  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsStatus("live");
        console.log("[WS] Connected");
      };

      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);

        if (msg.type === "alert") {
          setAlerts(prev => [msg.data, ...prev.slice(0, 29)]);
          setNewAlert(true);
          setTimeout(() => setNewAlert(false), 2000);
        }

        if (msg.type === "stats") {
          setStats(prev => ({ ...prev, ...msg.data }));
          setHistory(prev => [...prev.slice(-20), {
            time: new Date().toLocaleTimeString("en", { hour12:false, hour:"2-digit", minute:"2-digit", second:"2-digit" }),
            flows:   msg.data.total_flows,
            attacks: msg.data.total_attacks,
          }]);
        }
      };

      ws.onerror = () => setWsStatus("offline");

      ws.onclose = () => {
        setWsStatus("offline");
        // Reconnect after 3s
        setTimeout(connect, 3000);
      };
    };

    connect();
    fetchAll(); // initial load

    // Fallback polling every 10s (in case WS misses something)
    const poll = setInterval(fetchAll, 10000);
    return () => {
      clearInterval(poll);
      wsRef.current?.close();
    };
  }, [fetchAll]);

  const blockIP   = async (ip) => { await axios.post(`${API}/block/${ip}`);   fetchAll(); };
  const unblockIP = async (ip) => { await axios.delete(`${API}/block/${ip}`); fetchAll(); };

  const pieData    = Object.entries(stats.attack_counts || {}).map(([name, value]) => ({ name, value }));
  const attackRate = stats.total_flows > 0 ? ((stats.total_attacks / stats.total_flows) * 100).toFixed(1) : 0;

  const wsColor = wsStatus === "live" ? "#30d158" : wsStatus === "connecting" ? "#ff9f0a" : "#ff3864";

  if (loading) return (
    <div style={{ display:"flex", justifyContent:"center", alignItems:"center", height:"100vh", background:"#080c14", color:"#4a5568", fontFamily:"monospace" }}>
      INITIALIZING AEGIS...
    </div>
  );

  return (
    <div style={S.root}>
      <style>{CSS}</style>

      {/* ── Header ── */}
      <header style={S.header}>
        <div style={S.logo}>
          <span style={S.logoIcon}>⬡</span>
          <div>
            <div style={S.logoTitle}>AEGIS</div>
            <div style={S.logoSub}>CYBER DEFENSE SYSTEM</div>
          </div>
        </div>

        <div style={S.tabs}>
          {["overview","alerts","defense","analytics"].map(t => (
            <button key={t}
              style={{ ...S.tab, ...(tab===t ? S.tabActive : {}) }}
              onClick={() => setTab(t)}>
              {t === "alerts" && newAlert
                ? <span style={{ color:"#ff3864", animation:"blink 0.5s ease infinite" }}>🚨 ALERTS</span>
                : t.toUpperCase()
              }
            </button>
          ))}
        </div>

        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <PulseDot color={wsColor} />
          <span style={{ color:"#4a5568", fontSize:11, fontFamily:"monospace" }}>
            {wsStatus === "live" ? "LIVE" : wsStatus === "connecting" ? "CONNECTING" : "OFFLINE"}
          </span>
        </div>
      </header>

      <main style={S.main}>

        {/* ════ OVERVIEW ════ */}
        {tab === "overview" && (
          <div style={S.fadeIn}>
            <div style={S.grid4}>
              <StatCard icon="📡" label="Total Flows"  value={<Counter value={stats.total_flows} />}   accent="#0a84ff" />
              <StatCard icon="✅" label="Benign"       value={<Counter value={stats.benign} />}        accent="#30d158" />
              <StatCard icon="🚨" label="Attacks"      value={<Counter value={stats.total_attacks} />} accent="#ff3864" />
              <StatCard icon="🛡️" label="Blocked IPs"  value={<Counter value={stats.blocked_ips?.length||0} />} accent="#ff9f0a" />
            </div>

            <div style={S.banner}>
              <div style={{ color:"#4a5568", fontSize:11, fontFamily:"monospace", marginBottom:8 }}>ATTACK RATE</div>
              <div style={{ display:"flex", alignItems:"baseline", gap:12 }}>
                <span style={{ fontSize:52, fontWeight:900, color: attackRate>10 ? "#ff3864":"#30d158", fontFamily:"monospace", lineHeight:1 }}>
                  {attackRate}%
                </span>
                <span style={{ color:"#4a5568", fontSize:13 }}>of all flows are malicious</span>
              </div>
              <div style={{ marginTop:12 }}><ThreatBar score={parseFloat(attackRate)} /></div>
            </div>

            <div style={S.grid2}>
              <div style={S.card}>
                <div style={S.cardHead}><span style={S.cardTitle}>TRAFFIC TIMELINE</span></div>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={history} margin={{ top:5, right:10, bottom:0, left:-20 }}>
                    <defs>
                      <linearGradient id="gBlue" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#0a84ff" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#0a84ff" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="gRed" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#ff3864" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#ff3864" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1c2333"/>
                    <XAxis dataKey="time" stroke="#2d3748" tick={{ fill:"#4a5568", fontSize:10 }}/>
                    <YAxis stroke="#2d3748" tick={{ fill:"#4a5568", fontSize:10 }}/>
                    <Tooltip contentStyle={{ background:"#0d1117", border:"1px solid #1c2333", borderRadius:8, fontSize:12 }}/>
                    <Area type="monotone" dataKey="flows"   stroke="#0a84ff" fill="url(#gBlue)" strokeWidth={2} dot={false}/>
                    <Area type="monotone" dataKey="attacks" stroke="#ff3864" fill="url(#gRed)"  strokeWidth={2} dot={false}/>
                  </AreaChart>
                </ResponsiveContainer>
                <div style={{ display:"flex", gap:16, marginTop:8 }}>
                  <LegendDot color="#0a84ff" label="Flows"/>
                  <LegendDot color="#ff3864" label="Attacks"/>
                </div>
              </div>

              <div style={S.card}>
                <div style={S.cardHead}><span style={S.cardTitle}>ATTACK DISTRIBUTION</span></div>
                {pieData.length === 0
                  ? <Empty text="No attacks detected"/>
                  : <>
                    <ResponsiveContainer width="100%" height={180}>
                      <PieChart>
                        <Pie data={pieData} dataKey="value" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3}>
                          {pieData.map((_,i) => <Cell key={i} fill={COLORS[i%COLORS.length]} style={{ filter:`drop-shadow(0 0 6px ${COLORS[i%COLORS.length]})` }}/>)}
                        </Pie>
                        <Tooltip contentStyle={{ background:"#0d1117", border:"1px solid #1c2333", borderRadius:8, fontSize:12 }}/>
                      </PieChart>
                    </ResponsiveContainer>
                    <div style={{ display:"flex", flexWrap:"wrap", gap:6, marginTop:4 }}>
                      {pieData.map((d,i) => (
                        <span key={i} style={{ ...S.tag, borderColor:COLORS[i%COLORS.length], color:COLORS[i%COLORS.length] }}>
                          {d.name}: {d.value}
                        </span>
                      ))}
                    </div>
                  </>
                }
              </div>
            </div>

            <div style={S.card}>
              <div style={S.cardHead}>
                <span style={S.cardTitle}>LATEST THREATS</span>
                <button style={S.viewAll} onClick={() => setTab("alerts")}>VIEW ALL →</button>
              </div>
              <AlertTable alerts={alerts.slice(0,5)} onBlock={blockIP} onUnblock={unblockIP} compact/>
            </div>
          </div>
        )}

        {/* ════ ALERTS ════ */}
        {tab === "alerts" && (
          <div style={S.fadeIn}>
            <div style={S.card}>
              <div style={S.cardHead}>
                <span style={S.cardTitle}>THREAT ALERTS</span>
                <span style={{ ...S.badge, background:"#ff386420", color:"#ff3864" }}>{alerts.length} EVENTS</span>
              </div>
              <AlertTable alerts={alerts} onBlock={blockIP} onUnblock={unblockIP}/>
            </div>
          </div>
        )}

        {/* ════ DEFENSE ════ */}
        {tab === "defense" && (
          <div style={S.fadeIn}>
            <div style={S.grid2}>
              <div style={S.card}>
                <div style={S.cardHead}>
                  <span style={S.cardTitle}>BLOCKED IPs</span>
                  <span style={{ ...S.badge, background:"#ff9f0a20", color:"#ff9f0a" }}>{stats.blocked_ips?.length||0} ACTIVE</span>
                </div>
                {!stats.blocked_ips?.length
                  ? <Empty text="No IPs currently blocked"/>
                  : stats.blocked_ips.map(ip => (
                    <div key={ip} style={S.ipRow}>
                      <span style={{ fontFamily:"monospace", fontSize:13, color:"#e2e8f0" }}>🔴 {ip}</span>
                      <button style={{ ...S.btnSm, color:"#30d158", borderColor:"#30d158" }} onClick={() => unblockIP(ip)}>UNBLOCK</button>
                    </div>
                  ))
                }
              </div>

              <div style={S.card}>
                <div style={S.cardHead}><span style={S.cardTitle}>DEFENSE LAYERS</span></div>
                {[
                  "L1 · IP Reputation (AbuseIPDB)",
                  "L2 · Adaptive Rate Limiting",
                  "L3 · GeoIP Country Blocking",
                  "L4 · Anomaly Risk Scoring",
                  "L5 · Auto-Unblock Backoff",
                  "L6 · Pattern Correlation",
                ].map(l => (
                  <div key={l} style={S.layerRow}>
                    <span style={{ color:"#a0aec0", fontSize:12, fontFamily:"monospace" }}>{l}</span>
                    <span style={{ display:"flex", alignItems:"center", gap:6, color:"#30d158", fontSize:11, fontWeight:700 }}>
                      <PulseDot color="#30d158"/> ACTIVE
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div style={S.card}>
              <div style={S.cardHead}><span style={S.cardTitle}>HIGH RISK IPs</span></div>
              {!defense.high_risk_ips?.length
                ? <Empty text="No high-risk IPs"/>
                : defense.high_risk_ips.map((r,i) => (
                  <div key={i} style={S.riskRow}>
                    <div style={{ flex:1 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
                        <span style={{ fontFamily:"monospace", fontSize:13, color:"#e2e8f0" }}>{r.ip}</span>
                        <span style={{ ...S.badge, background:getRiskColor(r.risk_score)+"20", color:getRiskColor(r.risk_score) }}>
                          {getRiskLabel(r.risk_score)}
                        </span>
                        <span style={{ color:"#4a5568", fontSize:11 }}>{r.country}</span>
                      </div>
                      <ThreatBar score={r.risk_score}/>
                    </div>
                    <div style={{ textAlign:"right", marginLeft:16 }}>
                      <div style={{ color:"#4a5568", fontSize:10, fontFamily:"monospace" }}>BLOCKED</div>
                      <div style={{ color:"#ff9f0a", fontSize:20, fontWeight:700 }}>{r.block_count}×</div>
                    </div>
                  </div>
                ))
              }
            </div>
          </div>
        )}

        {/* ════ ANALYTICS ════ */}
        {tab === "analytics" && (
          <div style={S.fadeIn}>
            <div style={S.card}>
              <div style={S.cardHead}><span style={S.cardTitle}>ATTACK FREQUENCY</span></div>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart
                  data={Object.entries(stats.attack_counts||{}).map(([name,value]) => ({ name:name.replace("Web Attack ","WA·"), value }))}
                  margin={{ top:5, right:20, bottom:60, left:0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1c2333"/>
                  <XAxis dataKey="name" stroke="#2d3748" tick={{ fill:"#4a5568", fontSize:10, angle:-35, textAnchor:"end" }}/>
                  <YAxis stroke="#2d3748" tick={{ fill:"#4a5568", fontSize:10 }}/>
                  <Tooltip contentStyle={{ background:"#0d1117", border:"1px solid #1c2333", borderRadius:8, fontSize:12 }}/>
                  <Bar dataKey="value" radius={[4,4,0,0]}>
                    {Object.keys(stats.attack_counts||{}).map((_,i) => (
                      <Cell key={i} fill={COLORS[i%COLORS.length]} style={{ filter:`drop-shadow(0 0 4px ${COLORS[i%COLORS.length]})` }}/>
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div style={S.grid4}>
              <MiniStat label="Attack Rate"  value={`${attackRate}%`}                                  color="#ff3864"/>
              <MiniStat label="Total IPs"    value={stats.total_ips_seen||0}                           color="#0a84ff"/>
              <MiniStat label="Attack Types" value={Object.keys(stats.attack_counts||{}).length}       color="#bf5af2"/>
              <MiniStat label="Blocked"      value={stats.blocked_ips?.length||0}                      color="#ff9f0a"/>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function StatCard({ icon, label, value, accent }) {
  return (
    <div style={{ ...S.card, borderTop:`2px solid ${accent}`, position:"relative", overflow:"hidden", marginBottom:0 }}>
      <div style={{ position:"absolute", top:-10, right:-10, fontSize:64, opacity:0.05 }}>{icon}</div>
      <div style={{ color:"#4a5568", fontSize:11, fontFamily:"monospace", marginBottom:8 }}>{label}</div>
      <div style={{ fontSize:36, fontWeight:900, color:accent, fontFamily:"monospace", lineHeight:1 }}>{value}</div>
    </div>
  );
}

function MiniStat({ label, value, color }) {
  return (
    <div style={{ ...S.card, textAlign:"center", marginBottom:0 }}>
      <div style={{ color:"#4a5568", fontSize:11, fontFamily:"monospace" }}>{label}</div>
      <div style={{ fontSize:28, fontWeight:900, color, fontFamily:"monospace", marginTop:4 }}>{value}</div>
    </div>
  );
}

function LegendDot({ color, label }) {
  return (
    <div style={{ display:"flex", alignItems:"center", gap:6 }}>
      <div style={{ width:12, height:3, background:color, borderRadius:2, boxShadow:`0 0 4px ${color}` }}/>
      <span style={{ color:"#4a5568", fontSize:11 }}>{label}</span>
    </div>
  );
}

function Empty({ text }) {
  return <div style={{ color:"#2d3748", textAlign:"center", padding:"32px 0", fontFamily:"monospace", fontSize:13 }}>— {text} —</div>;
}

function AlertTable({ alerts, onBlock, onUnblock, compact }) {
  if (!alerts.length) return <Empty text="No alerts"/>;
  return (
    <div style={{ overflowX:"auto" }}>
      <table style={S.table}>
        <thead>
          <tr>
            {["Time","Source IP","Attack Type", !compact && "Confidence", !compact && "Risk Score","Status","Action"]
              .filter(Boolean).map(h => <th key={h} style={S.th}>{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {alerts.map((a,i) => {
            const icon = ATTACK_ICONS[a.label] || ATTACK_ICONS["default"];
            return (
              <tr key={i} style={{ ...S.tr, animation:`fadeIn 0.3s ease ${i*0.03}s both` }}>
                <td style={S.td}><span style={S.mono}>{new Date(a.timestamp).toLocaleTimeString()}</span></td>
                <td style={S.td}><span style={{ ...S.mono, color:"#0a84ff" }}>{a.src_ip}</span></td>
                <td style={S.td}><span style={{ color:"#ff3864", fontWeight:700 }}>{icon} {a.label}</span></td>
                {!compact && <td style={S.td}><span style={S.mono}>{a.confidence}%</span></td>}
                {!compact && <td style={{ ...S.td, minWidth:100 }}><ThreatBar score={a.risk_score||0}/></td>}
                <td style={S.td}>
                  <span style={{ color:a.blocked?"#ff3864":"#30d158", fontSize:11, fontWeight:700 }}>
                    {a.blocked ? "⛔ BLOCKED" : "⚠️ ACTIVE"}
                  </span>
                </td>
                <td style={S.td}>
                  {a.blocked
                    ? <button style={{ ...S.btnSm, color:"#30d158", borderColor:"#30d158" }} onClick={() => onUnblock(a.src_ip)}>UNBLOCK</button>
                    : <button style={{ ...S.btnSm, color:"#ff3864", borderColor:"#ff3864" }} onClick={() => onBlock(a.src_ip)}>BLOCK</button>
                  }
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

const S = {
  root:      { background:"#080c14", minHeight:"100vh", color:"#e2e8f0", fontFamily:"'DM Mono', monospace" },
  header:    { display:"flex", alignItems:"center", justifyContent:"space-between", padding:"16px 28px", borderBottom:"1px solid #0d1117", background:"#080c14", position:"sticky", top:0, zIndex:100 },
  logo:      { display:"flex", alignItems:"center", gap:12 },
  logoIcon:  { fontSize:28, color:"#0a84ff", filter:"drop-shadow(0 0 8px #0a84ff)" },
  logoTitle: { fontSize:18, fontWeight:900, color:"#e2e8f0", letterSpacing:4 },
  logoSub:   { fontSize:9, color:"#2d3748", letterSpacing:3 },
  tabs:      { display:"flex", gap:4 },
  tab:       { background:"none", border:"none", color:"#4a5568", fontSize:11, padding:"6px 14px", cursor:"pointer", letterSpacing:2, borderRadius:4, transition:"all 0.2s" },
  tabActive: { color:"#0a84ff", background:"#0a84ff15", borderBottom:"2px solid #0a84ff" },
  main:      { padding:"24px 28px", maxWidth:1400, margin:"0 auto" },
  fadeIn:    { animation:"fadeIn 0.4s ease" },
  grid4:     { display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:16 },
  grid2:     { display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:16, marginBottom:16 },
  card:      { background:"#0d1117", border:"1px solid #1c2333", borderRadius:12, padding:"18px 20px", marginBottom:16 },
  cardHead:  { display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 },
  cardTitle: { fontSize:11, fontWeight:700, color:"#4a5568", letterSpacing:3 },
  banner:    { background:"#0d1117", border:"1px solid #1c2333", borderRadius:12, padding:"20px 24px", marginBottom:16 },
  table:     { width:"100%", borderCollapse:"collapse" },
  th:        { textAlign:"left", padding:"10px 12px", fontSize:10, color:"#2d3748", letterSpacing:2, borderBottom:"1px solid #1c2333" },
  tr:        { borderBottom:"1px solid #0d1117" },
  td:        { padding:"10px 12px", fontSize:12 },
  mono:      { fontFamily:"monospace", color:"#a0aec0" },
  badge:     { fontSize:10, fontWeight:700, padding:"3px 8px", borderRadius:4, letterSpacing:1 },
  tag:       { fontSize:10, padding:"2px 8px", borderRadius:4, border:"1px solid", letterSpacing:1 },
  btnSm:     { background:"none", border:"1px solid #2d3748", color:"#a0aec0", borderRadius:4, padding:"3px 10px", cursor:"pointer", fontSize:10, letterSpacing:1, fontFamily:"monospace" },
  viewAll:   { background:"none", border:"none", color:"#0a84ff", fontSize:11, cursor:"pointer", letterSpacing:1 },
  ipRow:     { display:"flex", justifyContent:"space-between", alignItems:"center", padding:"10px 0", borderBottom:"1px solid #1c2333" },
  layerRow:  { display:"flex", justifyContent:"space-between", alignItems:"center", padding:"10px 0", borderBottom:"1px solid #0d1117" },
  riskRow:   { display:"flex", alignItems:"center", padding:"12px 0", borderBottom:"1px solid #1c2333" },
};

const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap');
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:#080c14; }
  @keyframes fadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }
  @keyframes pulse  { 0%,100% { transform:scale(1); opacity:1; } 50% { transform:scale(2); opacity:0; } }
  @keyframes blink  { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
  ::-webkit-scrollbar { width:4px; height:4px; }
  ::-webkit-scrollbar-track { background:#080c14; }
  ::-webkit-scrollbar-thumb { background:#1c2333; border-radius:2px; }
  tr:hover td { background:#0d1117; }
  button:hover { opacity:0.8; }
`;