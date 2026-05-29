import { FormEvent } from "react";

import { DataTable } from "../components/DataTable";
import { KeyForm, KeyItem } from "../types";

type KeysPageProps = {
  busy: boolean;
  editingKeyId: number | null;
  isAdmin: boolean;
  keyForm: KeyForm;
  keys: KeyItem[];
  onDeleteKey: (id: number) => void;
  onEditKey: (item: KeyItem) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  setKeyForm: React.Dispatch<React.SetStateAction<KeyForm>>;
};

export function KeysPage(props: KeysPageProps) {
  return (
    <section className="panel">
      <div className="section-head">
        <h3>Управление ключами</h3>
        <span>{props.isAdmin ? "CRUD для таблицы keys" : "Только просмотр"}</span>
      </div>

      {props.isAdmin ? (
        <form className="editor-grid" onSubmit={props.onSubmit}>
          <label className="field">
            <span>Имя</span>
            <input
              value={props.keyForm.name}
              onChange={(event) =>
                props.setKeyForm((current) => ({ ...current, name: event.target.value }))
              }
            />
          </label>
          <label className="field">
            <span>Значение ключа</span>
            <input
              value={props.keyForm.value}
              onChange={(event) =>
                props.setKeyForm((current) => ({ ...current, value: event.target.value }))
              }
            />
          </label>
          <label className="field field-wide">
            <span>Описание</span>
            <input
              value={props.keyForm.description}
              onChange={(event) =>
                props.setKeyForm((current) => ({
                  ...current,
                  description: event.target.value,
                }))
              }
            />
          </label>
          <div className="form-actions">
            <button className="primary-button" type="submit" disabled={props.busy}>
              {props.editingKeyId ? "Сохранить" : "Создать"}
            </button>
          </div>
        </form>
      ) : null}

      <DataTable
        headers={["ID", "Имя", "Значение", "Описание", "Действия"]}
        rows={props.keys.map((item) => (
          <tr key={item.id}>
            <td>{item.id}</td>
            <td>{item.name}</td>
            <td>{item.value}</td>
            <td>{item.description}</td>
            <td>
              {props.isAdmin ? (
                <div className="table-actions">
                  <button className="secondary-button" onClick={() => props.onEditKey(item)}>
                    Изменить
                  </button>
                  <button className="danger-button" onClick={() => props.onDeleteKey(item.id)}>
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
