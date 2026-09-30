import React, { useState } from 'react';
import {
  Zap,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Download,
  Flame,
  ShieldCheck,
  TrendingUp,
  RefreshCw
} from 'lucide-react';
import { LatencyMetric } from '../types/custody';

interface LatencyMonitorViewProps {
  metrics: LatencyMetric[];
  onTriggerTrafficSpike: () => void;
  onClearAlerts: () => void;
}

export const LatencyMonitorView: React.FC<LatencyMonitorViewProps> = ({
  metrics,
  onTriggerTrafficSpike,
  onClearAlerts
}) => {
  const breaches = metrics.filter(m => m.status === 'breach');
  const hasBreaches = breaches.length > 0;

  // Compute averages
  const gwMetrics = metrics.filter(m => m.service === 'git_gateway');
  const scanMetrics = metrics.filter(m => m.service === 'secret_scanner');
  const authMetrics = metrics.filter(m => m.service === 'api_auth');

  const avgGw = gwMetrics.length ? Math.round(gwMetrics.reduce((a, b) => a + b.latency_ms, 0) / gwMetrics.length) : 42;
  const avgScan = scanMetrics.length ? Math.round(scanMetrics.reduce((a, b) => a + b.latency_ms, 0) / scanMetrics.length) : 58;
  const avgAuth = authMetrics.length ? Math.round(authMetrics.reduce((a, b) => a + b.latency_ms, 0) / authMetrics.length) : 19;

  const exportMetrics = () => {
    const jsonStr = JSON.stringify(metrics, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `custody-latency-metrics-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${hasBreaches ? 'bg-rose-500 animate-ping' : 'bg-emerald-400 animate-pulse'}`} />
            <h2 className="text-lg font-bold text-zinc-100 flex items-center gap-2">
              Performance & Latency Telemetry Dashboard
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold border ${
                hasBreaches
                  ? 'bg-rose-950 text-rose-300 border-rose-800'
                  : 'bg-zinc-800 text-emerald-300 border-emerald-900/60'
              }`}>
                {hasBreaches ? 'Threshold Breach Detected' : 'All Services Optimal'}
              </span>
            </h2>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed max-w-2xl">
            Real-time latency metrics for the platform Git Gateway, pre-receive secret scanning, and Temporal door lifecycle workflows. Automated alerts trigger when SLAs breach.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={onTriggerTrafficSpike}
            className="bg-zinc-900 hover:bg-zinc-800 text-amber-300 border border-amber-800/40 text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-1.5 transition-colors"
            title="Simulate a high-concurrency peak traffic spike"
          >
            <Flame className="w-3.5 h-3.5 text-amber-400" />
            <span>Simulate Traffic Spike</span>
          </button>

          {hasBreaches && (
            <button
              onClick={onClearAlerts}
              className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs font-medium px-3 py-2.5 rounded-xl flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Clear Alerts</span>
            </button>
          )}

          <button
            onClick={exportMetrics}
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2 transition-colors shadow-lg shadow-indigo-600/20"
          >
            <Download className="w-4 h-4" />
            <span>Export Metrics JSON</span>
          </button>
        </div>
      </div>

      {/* Automated Alert Banner if breach exists */}
      {hasBreaches && (
        <div className="bg-rose-950/60 border border-rose-700/80 rounded-2xl p-4 flex items-start gap-3.5 text-xs text-rose-200 animate-in fade-in duration-200">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1 flex-1">
            <div className="font-bold text-sm text-rose-100 flex items-center gap-2">
              <span>Automated Alert: Latency Threshold Breach Detected</span>
              <span className="text-[10px] bg-rose-900 px-2 py-0.5 rounded font-mono font-medium">
                P99 Alert
              </span>
            </div>
            <p className="text-[11px] text-rose-200/90 leading-relaxed">
              One or more Git Gateway requests exceeded acceptable operating parameters ({breaches.map(b => `${b.service}: ${b.latency_ms}ms > ${b.threshold_ms}ms`).join(', ')}).
              Automated horizontal pod autoscaling (HPA) in Kubernetes has been notified.
            </p>
          </div>
        </div>
      )}

      {/* Key Metric Tiles */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
        <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 font-medium">
            <Zap className="w-4 h-4 text-indigo-400" />
            <span>Git Gateway Latency (Avg)</span>
          </div>
          <div className="text-2xl font-bold text-zinc-100 font-mono">
            {avgGw} <span className="text-xs text-zinc-500 font-normal">ms</span>
          </div>
          <span className="text-[11px] text-emerald-400 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            Target: &lt; 250ms SLA
          </span>
        </div>

        <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 font-medium">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Secret Scanner AST Pass</span>
          </div>
          <div className="text-2xl font-bold text-zinc-100 font-mono">
            {avgScan} <span className="text-xs text-zinc-500 font-normal">ms</span>
          </div>
          <span className="text-[11px] text-zinc-400">
            Pre-receive Gitleaks inspection
          </span>
        </div>

        <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 font-medium">
            <Clock className="w-4 h-4 text-amber-400" />
            <span>API Authorize Check</span>
          </div>
          <div className="text-2xl font-bold text-zinc-100 font-mono">
            {avgAuth} <span className="text-xs text-zinc-500 font-normal">ms</span>
          </div>
          <span className="text-[11px] text-zinc-400">
            Cached &lt; 5s per spec
          </span>
        </div>
      </div>

      {/* Latency Telemetry Stream Table */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl overflow-hidden shadow-xl space-y-3 p-5">
        <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-zinc-400" />
            <h3 className="font-semibold text-zinc-100 text-xs uppercase tracking-wider">
              Live Latency Telemetry Stream
            </h3>
          </div>
          <span className="text-[11px] text-zinc-500 font-mono">Real-Time Event Buffer</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-zinc-900/80 text-zinc-400 border-b border-zinc-800">
              <tr>
                <th className="p-3">Service</th>
                <th className="p-3">Endpoint / Hook</th>
                <th className="p-3">Latency</th>
                <th className="p-3">Threshold</th>
                <th className="p-3">Status</th>
                <th className="p-3">Recorded At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 text-zinc-300">
              {metrics.map((m) => (
                <tr key={m.id} className="hover:bg-zinc-900/40 transition-colors">
                  <td className="p-3 font-semibold text-zinc-100">
                    {m.service}
                  </td>
                  <td className="p-3 text-zinc-400 text-[11px]">
                    {m.endpoint}
                  </td>
                  <td className="p-3 font-bold">
                    <span className={m.status === 'breach' ? 'text-rose-400' : 'text-emerald-400'}>
                      {m.latency_ms} ms
                    </span>
                  </td>
                  <td className="p-3 text-zinc-500">
                    {m.threshold_ms} ms
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                      m.status === 'breach'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}>
                      {m.status}
                    </span>
                  </td>
                  <td className="p-3 text-zinc-500 text-[11px]">
                    {new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
