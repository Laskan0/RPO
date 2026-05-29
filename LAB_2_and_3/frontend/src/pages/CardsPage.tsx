import { FormEvent } from "react";

import { DataTable } from "../components/DataTable";
import { CardForm, CardItem, KeyItem } from "../types";

type CardsPageProps = {
  busy: boolean;
  cardForm: CardForm;
  cards: CardItem[];
  editingCardId: number | null;
  isAdmin: boolean;
  keys: KeyItem[];
  onCancelEdit: () => void;
  onDeleteCard: (id: number) => void;
  onEditCard: (item: CardItem) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  setCardForm: React.Dispatch<React.SetStateAction<CardForm>>;
};

export function CardsPage(props: CardsPageProps) {
  return (
    <section className="panel">
      <div className="section-head">
        <h3>Управление картами</h3>
        <span>{props.isAdmin ? "Связка cards + keys" : "Только просмотр"}</span>
      </div>

      {props.isAdmin ? (
        <form className="editor-grid editor-grid-4" onSubmit={props.onSubmit}>
          <label className="field">
            <span>Номер карты</span>
            <input
              value={props.cardForm.card_number}
              onChange={(event) =>
                props.setCardForm((current) => ({ ...current, card_number: event.target.value }))
              }
            />
          </label>
          <label className="field">
            <span>Владелец</span>
            <input
              value={props.cardForm.owner_name}
              onChange={(event) =>
                props.setCardForm((current) => ({ ...current, owner_name: event.target.value }))
              }
            />
          </label>
          <label className="field">
            <span>Баланс</span>
            <input
              type="number"
              value={props.cardForm.balance}
              onChange={(event) =>
                props.setCardForm((current) => ({ ...current, balance: event.target.value }))
              }
            />
          </label>
          <label className="field">
            <span>Key ID</span>
            <select
              value={props.cardForm.key_id}
              onChange={(event) =>
                props.setCardForm((current) => ({ ...current, key_id: event.target.value }))
              }
            >
              <option value="">Выберите ключ</option>
              {props.keys.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.id} - {item.name}
                </option>
              ))}
            </select>
          </label>
          <label className="toggle-field">
            <span>Карта заблокирована</span>
            <input
              type="checkbox"
              checked={props.cardForm.is_blocked}
              onChange={(event) =>
                props.setCardForm((current) => ({
                  ...current,
                  is_blocked: event.target.checked,
                }))
              }
            />
          </label>
          <div className="form-actions">
            <button className="primary-button" type="submit" disabled={props.busy}>
              {props.editingCardId ? "Сохранить" : "Создать"}
            </button>
            {props.editingCardId ? (
              <button className="secondary-button" type="button" onClick={props.onCancelEdit}>
                Отмена
              </button>
            ) : null}
          </div>
        </form>
      ) : null}

      <DataTable
        headers={[
          "ID",
          "Номер карты",
          "Владелец",
          "Баланс",
          "Заблокирована",
          "Key ID",
          "Действия",
        ]}
        rows={props.cards.map((item) => (
          <tr key={item.id}>
            <td>{item.id}</td>
            <td>{item.card_number}</td>
            <td>{item.owner_name}</td>
            <td>{item.balance}</td>
            <td>{item.is_blocked ? "Да" : "Нет"}</td>
            <td>{item.key_id}</td>
            <td>
              {props.isAdmin ? (
                <div className="table-actions">
                  <button className="secondary-button" onClick={() => props.onEditCard(item)}>
                    Изменить
                  </button>
                  <button className="danger-button" onClick={() => props.onDeleteCard(item.id)}>
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
