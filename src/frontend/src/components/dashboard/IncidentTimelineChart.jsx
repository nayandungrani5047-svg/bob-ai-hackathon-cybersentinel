import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
);

export default function IncidentTimelineChart({ data = [] }) {
  const labels = data.map((d) => d.hour);
  const values = data.map((d) => d.count);

  const chartData = {
    labels,
    datasets: [
      {
        label: 'Incidents',
        data: values,
        borderColor: '#00bcd4',
        backgroundColor: 'rgba(0, 188, 212, 0.12)',
        pointBackgroundColor: '#00bcd4',
        pointBorderColor: '#0d1117',
        pointRadius: 4,
        pointHoverRadius: 6,
        borderWidth: 2,
        fill: true,
        tension: 0.35,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          label: (ctx) => ` ${ctx.parsed.y} incident${ctx.parsed.y !== 1 ? 's' : ''}`,
        },
      },
    },
    scales: {
      x: {
        ticks: { color: '#8b949e', font: { size: 11 }, maxRotation: 45 },
        grid: { color: '#21262d' },
        border: { color: '#21262d' },
      },
      y: {
        beginAtZero: true,
        ticks: {
          color: '#8b949e',
          font: { size: 11 },
          precision: 0,
          stepSize: 1,
        },
        grid: { color: '#21262d' },
        border: { color: '#21262d' },
      },
    },
  };

  return (
    <div className="relative h-[200px]">
      <Line data={chartData} options={options} />
    </div>
  );
}
