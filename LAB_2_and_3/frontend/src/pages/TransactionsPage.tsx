import { DataTable } from "../components/DataTable";
import { TransactionItem } from "../types";
import { formatDate } from "../utils";

type TransactionsPageProps = {
  isAdmin: boolean;
  onRefresh: () => void;
  transactions: TransactionItem[];
};

export function TransactionsPage(props: TransactionsPageProps) {
  return (
    <section className="panel">
      <div className="section-head">
        <h3>Журнал транзакций</h3>
        {props.isAdmin ? (
          <button className="primary-button" type="button" onClick={props.onRefresh}>
            Обновить список
          </button>
        ) : (
          <span>Только просмотр</span>
        )}
      </div>

      <DataTable
        headers={["ID", "Сумма", "Card ID", "Terminal ID", "Авторизована", "Дата"]}
        rows={props.transactions.map((item) => (
          <tr key={item.id}>
            <td>{item.id}</td>
            <td>{item.amount}</td>
            <td>{item.card_id}</td>
            <td>{item.terminal_id}</td>
            <td>{item.authorized ? "Да" : "Нет"}</td>
            <td>{formatDate(item.created_at)}</td>
          </tr>
        ))}
      />
    </section>
  );
}
