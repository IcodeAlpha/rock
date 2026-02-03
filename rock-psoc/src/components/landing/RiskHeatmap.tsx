import { motion } from 'motion/react'
import { Grid3X3, Info } from 'lucide-react'

const assetCategories = [
  'Identity & Access',
  'Network Perimeter',
  'Endpoints',
  'Cloud Infrastructure',
  'Data Stores',
  'Applications',
]

const threatTypes = [
  'Ransomware',
  'Phishing',
  'DDoS',
  'Supply Chain',
  'Insider',
  'Zero-Day',
]

// Risk scores (0-100) for each cell
const riskMatrix = [
  [85, 92, 45, 38, 72, 28], // Identity & Access
  [62, 55, 88, 42, 35, 65], // Network Perimeter
  [78, 82, 52, 68, 45, 72], // Endpoints
  [55, 48, 75, 82, 88, 58], // Cloud Infrastructure
  [92, 65, 32, 55, 95, 42], // Data Stores
  [68, 78, 45, 88, 62, 85], // Applications
]

function getRiskColor(score: number): string {
  if (score >= 80) return 'bg-red-500'
  if (score >= 60) return 'bg-amber-500'
  if (score >= 40) return 'bg-yellow-500'
  return 'bg-emerald-500'
}

function getRiskOpacity(score: number): string {
  if (score >= 80) return 'opacity-90'
  if (score >= 60) return 'opacity-70'
  if (score >= 40) return 'opacity-50'
  return 'opacity-40'
}

export function RiskHeatmap() {
  return (
    <section className="relative py-24 bg-[#0a0f1a]">
      <div className="max-w-6xl mx-auto px-6">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-amber-500/30 bg-amber-500/5 mb-6">
            <Grid3X3 className="h-4 w-4 text-amber-400" />
            <span className="text-amber-400 text-sm font-mono">
              RISK VISUALIZATION
            </span>
          </div>
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Asset Risk Heatmap
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Instantly identify where your highest risks concentrate.
            Cross-reference asset categories against threat types to prioritize
            defensive resources.
          </p>
        </motion.div>

        {/* Heatmap container */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="relative p-6 md:p-8 rounded-2xl border border-slate-800 bg-slate-900/50 backdrop-blur overflow-x-auto"
        >
          {/* Legend */}
          <div className="flex items-center justify-between mb-8 flex-wrap gap-4">
            <div className="flex items-center gap-2 text-slate-400 text-sm">
              <Info className="h-4 w-4" />
              <span>
                Risk scores based on OSINT correlation and historical patterns
              </span>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-emerald-500 opacity-40" />
                <span className="text-xs text-slate-500">Low</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-yellow-500 opacity-50" />
                <span className="text-xs text-slate-500">Medium</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-amber-500 opacity-70" />
                <span className="text-xs text-slate-500">High</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-red-500 opacity-90" />
                <span className="text-xs text-slate-500">Critical</span>
              </div>
            </div>
          </div>

          {/* Heatmap grid */}
          <div className="min-w-[600px]">
            {/* Header row - threat types */}
            <div className="grid grid-cols-7 gap-2 mb-2">
              <div /> {/* Empty corner cell */}
              {threatTypes.map((threat) => (
                <div
                  key={threat}
                  className="text-center text-xs font-mono text-slate-500 py-2 truncate"
                  title={threat}
                >
                  {threat}
                </div>
              ))}
            </div>

            {/* Data rows */}
            {assetCategories.map((category, rowIndex) => (
              <div key={category} className="grid grid-cols-7 gap-2 mb-2">
                {/* Row label */}
                <div
                  className="flex items-center text-xs font-mono text-slate-500 pr-2 truncate"
                  title={category}
                >
                  {category}
                </div>

                {/* Risk cells */}
                {riskMatrix[rowIndex].map((score, colIndex) => (
                  <motion.div
                    key={`${rowIndex}-${colIndex}`}
                    initial={{ opacity: 0, scale: 0.8 }}
                    whileInView={{ opacity: 1, scale: 1 }}
                    viewport={{ once: true }}
                    transition={{
                      duration: 0.3,
                      delay: (rowIndex * 6 + colIndex) * 0.02,
                    }}
                    className="group relative"
                  >
                    <div
                      className={`aspect-square rounded-lg ${getRiskColor(score)} ${getRiskOpacity(score)} flex items-center justify-center cursor-pointer hover:opacity-100 transition-all duration-200 hover:scale-105`}
                    >
                      <span className="text-xs font-mono text-white/90 opacity-0 group-hover:opacity-100 transition-opacity">
                        {score}
                      </span>
                    </div>

                    {/* Tooltip */}
                    <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 bg-slate-800 rounded-lg text-xs opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10 border border-slate-700">
                      <div className="text-white font-semibold">{category}</div>
                      <div className="text-slate-400">
                        {threatTypes[colIndex]}: {score}% risk
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            ))}
          </div>

          {/* Summary stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8 pt-8 border-t border-slate-800">
            <div className="text-center">
              <div className="text-2xl font-bold text-red-400 font-mono">
                12
              </div>
              <div className="text-xs text-slate-500">Critical Zones</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-amber-400 font-mono">
                18
              </div>
              <div className="text-xs text-slate-500">High Risk Areas</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-cyan-400 font-mono">
                Data Stores
              </div>
              <div className="text-xs text-slate-500">
                Highest Risk Category
              </div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-emerald-400 font-mono">
                DDoS
              </div>
              <div className="text-xs text-slate-500">Lowest Avg. Threat</div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}