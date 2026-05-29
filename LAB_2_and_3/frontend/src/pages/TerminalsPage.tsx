import { FormEvent } from "react";

import { DataTable } from "../components/DataTable";
import { TerminalForm, TerminalItem } from "../types";

type TerminalsPageProps = {
  busy: boolean;
  editingTerminalId: number | null;
  isAdmin: boolean;
  onDeleteTerminal: (id: number) => void;
  onEditTerminal: (item: TerminalItem) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  setTerminalForm: React.Dispatch<React.SetStateAction<TerminalForm>>;
  terminalForm: TerminalForm;
  terminals: TerminalItem[];
};

export function TerminalsPage(props: TerminalsPageProps) {
  return (
    <section className="panel">
      <div className="section-head">
        <h3>Управление терминалами</h3>
        <span>{props.isAdmin ? "CRUD для таблицы terminals" : "Только просмотр"}</span>
      </div>

      {props.isAdmin ? (
        <form className="editor-grid editor-grid-3" onSubmit={props.onSubmit}>
          <label className="field">
            <span>Серийный номер</span>
            <input
              value={props.terminalForm.serial_number}
              onChange={(event) =>
                props.setTerminalForm((current) => ({
                  ...current,
                  serial_number: event.target.value,
                }))
              }
            />
          </label>
          <label className="field">
            <span>Название</span>
            <input
              value={props.terminalForm.name}
              onChange={(event) =>
                props.setTerminalForm((current) => ({ ...current, name: event.target.value }))
              }
            />
          </label>
          <label className="field">
            <span>Адрес</span>
            <input
              value={props.terminalForm.address}
              onChange={(event) =>
                props.setTerminalForm((current) => ({ ...current, address: event.target.value }))
              }
            />
          </label>
          <label className="toggle-field">
            <span>Активен</span>
            <input
              type="checkbox"
              checked={props.terminalForm.is_active}
              onChange={(event) =>
                props.setTerminalForm((current) => ({
                  ...current,
                  is_active: event.target.checked,
                }))
              }
            />
          </label>
          <div className="form-actions">
            <button className="primary-button" type="submit" disabled={props.busy}>
              {props.editingTerminalId ? "Сохранить" : "Создать"}
            </button>
          </div>
        </form>
      ) : null}

      <DataTable
        headers={["ID", "Серийный номер", "Название", "Адрес", "Активен", "Действия"]}
        rows={props.terminals.map((item) => (
          <tr key={item.id}>
            <td>{item.id}</td>
            <td>{item.serial_number}</td>
            <td>{item.name}</td>
            <td>{item.address}</td>
            <td>{item.is_active ? "Да" : "Нет"}</td>
            <td>
              {props.isAdmin ? (
                <div className="table-actions">
                  <button className="secondary-button" onClick={() => props.onEditTerminal(item)}>
                    Изменить
                  </button>
                  <button className="danger-button" onClick={() => props.onDeleteTerminal(item.id)}>
                    Удалить
                  </button>
                </div>
              ) : (
                "Только просмотр"
              )}
            </td>
          </tr>
        ))}
      />
    </section>
  );
}
