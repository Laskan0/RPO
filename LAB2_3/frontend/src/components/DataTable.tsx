import { ReactNode } from "react";

export function DataTable(props: { headers: string[]; rows: ReactNode[] }) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            {props.headers.map((header) => (
              <th key={header}>{header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {props.rows.length > 0 ? (
            props.rows
          ) : (
            <tr>
              <td className="empty-cell" colSpan={props.headers.length}>
                Данных пока нет.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
