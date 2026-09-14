import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend);

const COLORS = {
  Critical: '#ff4444',
  High: '#ff8c00',
  Medium: '#ffd700',
  Low: '#00cc88',
};

export default function SeverityChart({ data = {} }) {
  const labels = ['Critical', 'High', 'Medium', 'Low'];
  const values = labels.map((l) => data[l] ?? 0);
  const total = values.reduce((a, b) => a + b, 0);

  if (total === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full min-h-[220px] text-[#8b949e] text-sm gap-2">
        <span className="text-3xl">🛡️</span>
        <span>No data — click <strong className="text-brand-cyan">Ingest Alerts</strong> to load</span>
      </div>
    );
  }

  const chartData = {
    labels,
    datasets: [
      {
        data: values,
        backgroundColor: labels.map((l) => COLORS[l]),
        borderColor: '#0d1117',
        borderWidth: 3,
        hoverOffset: 6,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#8b949e',
          padding: 14,
          boxWidth: 12,
          font: { size: 12 },
        },
      },
      tooltip: {
        callbacks: {
          label: (ctx) => ` ${ctx.label}: ${ctx.parsed} alerts`,
        },
      },
    },
    cutout: '65%',
  };

  return (
    <div className="relative h-[220px]">
      <Doughnut data={chartData} options={options} />
    </div>
  );
}
