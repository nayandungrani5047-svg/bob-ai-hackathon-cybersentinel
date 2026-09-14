import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

export default function AlertsBySourceChart({ data = {} }) {
  const labels = Object.keys(data);
  const values = Object.values(data);

  const chartData = {
    labels,
    datasets: [
      {
        label: 'Alerts',
        data: values,
        backgroundColor: 'rgba(0, 188, 212, 0.7)',
        borderColor: '#00bcd4',
        borderWidth: 1,
        borderRadius: 4,
      },
    ],
  };

  const options = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          label: (ctx) => ` ${ctx.parsed.x} alerts`,
        },
      },
    },
    scales: {
      x: {
        ticks: { color: '#8b949e', font: { size: 11 } },
        grid: { color: '#21262d' },
        border: { color: '#21262d' },
      },
      y: {
        ticks: { color: '#8b949e', font: { size: 11 } },
        grid: { color: 'transparent' },
        border: { color: '#21262d' },
      },
    },
  };

  return (
    <div className="relative" style={{ height: `${Math.max(180, labels.length * 36 + 40)}px` }}>
      <Bar data={chartData} options={options} />
    </div>
  );
}
