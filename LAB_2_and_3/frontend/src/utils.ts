import {
  CardForm,
  KeyForm,
  TerminalForm,
  TerminalToolsForm,
  UserForm,
  ViewKey,
} from "./types";

export const apiBase = "/api/v1";

export const navItems: Array<{ key: ViewKey; label: string }> = [
  { key: "dashboard", label: "Главная" },
  { key: "users", label: "Пользователи" },
  { key: "terminals", label: "Терминалы" },
  { key: "cards", label: "Карты" },
  { key: "keys", label: "Ключи" },
  { key: "transactions", label: "Транзакции" },
  { key: "terminal", label: "Терминал" },
];

export function titleForView(view: ViewKey): string {
  switch (view) {
    case "dashboard":
      return "Панель управления сервером";
    case "users":
      return "Пользователи";
    case "terminals":
      return "Терминалы";
    case "cards":
      return "Карты";
    case "keys":
      return "Ключи";
    case "transactions":
      return "Транзакции";
    case "terminal":
      return "Инструменты терминала";
  }
}

export function subtitleForView(view: ViewKey): string {
  switch (view) {
    case "dashboard":
      return "";
    case "users":
      return "";
    case "terminals":
      return "";
    case "cards":
      return "";
    case "keys":
      return "";
    case "transactions":
      return "";
    case "terminal":
      return "";
  }
}

export function readViewFromHash(): ViewKey {
  const raw = window.location.hash.replace("#", "");
  if (navItems.some((item) => item.key === raw)) {
    return raw as ViewKey;
  }

  return "dashboard";
}

export function formatDate(value?: string) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("ru-RU", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(date);
}

export function toErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Произошла ошибка.";
}

export function validateUserForm(form: UserForm, isEditing: boolean): string | null {
  if (!form.login.trim()) {
    return "Укажите логин пользователя.";
  }
  if (!form.full_name.trim()) {
    return "Укажите имя пользователя.";
  }
  if (!isEditing && !form.password.trim()) {
    return "Укажите пароль пользователя.";
  }
  if (form.password && form.password.trim().length > 0 && form.password.trim().length < 4) {
    return "Пароль должен содержать минимум 4 символа.";
  }
  return null;
}

export function validateTerminalForm(form: TerminalForm): string | null {
  if (!form.serial_number.trim()) {
    return "Укажите серийный номер терминала.";
  }
  if (!form.name.trim()) {
    return "Укажите название терминала.";
  }
  if (!form.address.trim()) {
    return "Укажите адрес терминала.";
  }
  return null;
}

export function validateCardForm(form: CardForm): string | null {
  if (!form.card_number.trim()) {
    return "Укажите номер карты.";
  }
  if (!form.owner_name.trim()) {
    return "Укажите владельца карты.";
  }
  if (form.balance.trim() === "" || Number.isNaN(Number(form.balance))) {
    return "Укажите корректный баланс.";
  }
  if (Number(form.balance) < 0) {
    return "Баланс не может быть отрицательным.";
  }
  if (!form.key_id.trim() || Number(form.key_id) <= 0) {
    return "Выберите ключ для карты.";
  }
  return null;
}

export function validateKeyForm(form: KeyForm): string | null {
  if (!form.name.trim()) {
    return "Укажите имя ключа.";
  }
  if (!form.value.trim()) {
    return "Укажите значение ключа.";
  }
  if (form.value.trim().length < 6) {
    return "Значение ключа должно содержать минимум 6 символов.";
  }
  return null;
}

export function validateTerminalTools(form: TerminalToolsForm): string | null {
  if (!form.card_number.trim()) {
    return "Укажите номер карты.";
  }
  if (!form.terminal_serial_number.trim()) {
    return "Укажите серийный номер терминала.";
  }
  if (form.amount.trim() === "" || Number.isNaN(Number(form.amount))) {
    return "Укажите корректную сумму.";
  }
  if (Number(form.amount) <= 0) {
    return "Сумма должна быть больше нуля.";
  }
  return null;
}
