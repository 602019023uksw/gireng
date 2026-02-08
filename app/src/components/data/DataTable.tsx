import { motion } from 'framer-motion';

interface TableColumn {
  key: string;
  header: string;
  width?: string;
}

interface TableRow {
  [key: string]: React.ReactNode;
}

interface DataTableProps {
  columns: TableColumn[];
  rows: TableRow[];
}

export function DataTable({ columns, rows }: DataTableProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="rounded-xl overflow-hidden my-4"
      style={{
        background: 'rgba(10, 14, 28, 0.6)',
        border: '1px solid rgba(100, 120, 180, 0.15)',
      }}
    >
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr
              style={{
                background: 'rgba(20, 28, 50, 0.5)',
                borderBottom: '1px solid rgba(100, 120, 180, 0.15)',
              }}
            >
              {columns.map((col) => (
                <th
                  key={col.key}
                  className="px-4 py-3 text-left text-sm font-semibold text-text-primary"
                  style={{ width: col.width }}
                >
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, rowIndex) => (
              <tr
                key={rowIndex}
                className="hover:bg-white/5 transition-colors duration-150"
                style={{
                  borderBottom: rowIndex < rows.length - 1 
                    ? '1px solid rgba(100, 120, 180, 0.1)' 
                    : 'none',
                }}
              >
                {columns.map((col) => (
                  <td key={col.key} className="px-4 py-3">
                    {row[col.key]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.div>
  );
}

export default DataTable;
