import { FormEvent } from "react";

import { DataTable } from "../components/DataTable";
import { User, UserForm } from "../types";
import { formatDate } from "../utils";

type UsersPageProps = {
  busy: boolean;
  editingUserId: number | null;
  isAdmin: boolean;
  onCancelEdit: () => void;
  onDeleteUser: (id: number) => void;
  onEditUser: (item: User) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  setUserForm: React.Dispatch<React.SetStateAction<UserForm>>;
  userForm: UserForm;
  users: User[];
};

export function UsersPage(props: UsersPageProps) {
  return (
    <section className="panel">
      <div className="section-head">
        <h3>Управление пользователями</h3>
        <span>{props.isAdmin ? "Полный доступ" : "Только собственный профиль"}</span>
      </div>

      {props.isAdmin ? (
        <form className="editor-grid" onSubmit={props.onSubmit}>
          <label className="field">
            <span>Логин</span>
            <input
              value={props.userForm.login}
              onChange={(event) =>
                props.setUserForm((current) => ({ ...current, login: event.target.value }))
              }
            />
          </label>
          <label className="field">
            <span>Имя</span>
            <input
              value={props.userForm.full_name}
              onChange={(event) =>
                props.setUserForm((current) => ({ ...current, full_name: event.target.value }))
              }
            />
          </label>
          <label className="field">
            <span>Пароль</span>
            <input
              type="password"
              value={props.userForm.password}
              onChange={(event) =>
                props.setUserForm((current) => ({ ...current, password: event.target.value }))
              }
            />
          </label>
          <label className="toggle-field">
            <span>Администратор</span>
            <input
              type="checkbox"
              checked={props.userForm.is_admin}
              onChange={(event) =>
                props.setUserForm((current) => ({ ...current, is_admin: event.target.checked }))
              }
            />
          </label>
          <div className="form-actions">
            <button className="primary-button" type="submit" disabled={props.busy}>
              {props.editingUserId ? "Сохранить" : "Создать"}
            </button>
            {props.editingUserId ? (
              <button className="secondary-button" type="button" onClick={props.onCancelEdit}>
                Отмена
              </button>
            ) : null}
          </div>
        </form>
      ) : null}

      <DataTable
        headers={["ID", "Логин", "Имя", "Админ", "Создан", "Действия"]}
        rows={props.users.map((item) => (
          <tr key={item.id}>
            <td>{item.id}</td>
            <td>{item.login}</td>
            <td>{item.full_name}</td>
            <td>{item.is_admin ? "Да" : "Нет"}</td>
            <td>{formatDate(item.created_at)}</td>
            <td>
              {props.isAdmin ? (
                <div className="table-actions">
                  <button className="secondary-button" onClick={() => props.onEditUser(item)}>
                    Изменить
                  </button>
                  <button className="danger-button" onClick={() => props.onDeleteUser(item.id)}>
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
