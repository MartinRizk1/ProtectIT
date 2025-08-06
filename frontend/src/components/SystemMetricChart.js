import React from 'react';
import { ResponsiveBar } from '@nivo/bar';
import { useTheme } from '../context/ThemeContext';

const SystemMetricChart = ({ data, height = 300 }) => {
  const { theme } = useTheme();

  // Configure colors based on values
  const getBarColor = (bar) => {
    const value = bar.value;
    if (value >= 90) return '#d32f2f'; // High usage - red
    if (value >= 70) return '#f57c00'; // Medium-high - orange
    if (value >= 50) return '#ffa000'; // Medium - amber
    return '#4caf50'; // Low - green
  };

  return (
    <div style={{ height: height }}>
      <ResponsiveBar
        data={data}
        keys={['value']}
        indexBy="name"
        margin={{ top: 10, right: 10, bottom: 50, left: 60 }}
        padding={0.3}
        valueScale={{ type: 'linear' }}
        indexScale={{ type: 'band', round: true }}
        colors={getBarColor}
        borderColor={{ from: 'color', modifiers: [['darker', 1.6]] }}
        axisTop={null}
        axisRight={null}
        axisBottom={{
          tickSize: 5,
          tickPadding: 5,
          tickRotation: 0,
          legend: 'Resource',
          legendPosition: 'middle',
          legendOffset: 32
        }}
        axisLeft={{
          tickSize: 5,
          tickPadding: 5,
          tickRotation: 0,
          legend: 'Usage %',
          legendPosition: 'middle',
          legendOffset: -40
        }}
        enableLabel={true}
        labelSkipWidth={12}
        labelSkipHeight={12}
        labelTextColor={{ from: 'color', modifiers: [['darker', 1.6]] }}
        animate={true}
        motionStiffness={90}
        motionDamping={15}
        theme={{
          axis: {
            ticks: {
              text: {
                fill: theme === 'dark' ? '#adb5bd' : '#495057',
              }
            },
            legend: {
              text: {
                fill: theme === 'dark' ? '#f8f9fa' : '#212529',
              }
            }
          },
          grid: {
            line: {
              stroke: theme === 'dark' ? '#495057' : '#dee2e6',
            }
          },
          tooltip: {
            container: {
              background: theme === 'dark' ? '#343a40' : '#ffffff',
              color: theme === 'dark' ? '#f8f9fa' : '#212529',
            }
          }
        }}
        markers={[
          {
            axis: 'y',
            value: 90,
            lineStyle: { stroke: '#d32f2f', strokeWidth: 2, strokeDasharray: '6 6' },
            legend: 'Critical',
            legendOrientation: 'vertical',
          },
          {
            axis: 'y',
            value: 70,
            lineStyle: { stroke: '#f57c00', strokeWidth: 1, strokeDasharray: '6 6' },
            legend: 'Warning',
            legendOrientation: 'vertical',
          }
        ]}
      />
    </div>
  );
};

export default SystemMetricChart;
