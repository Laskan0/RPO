export type ViewKey =
  | "dashboard"
  | "users"
  | "terminals"
  | "cards"
  | "keys"
  | "transactions"
  | "terminal";

export type User = {
  id: number;
  login: string;
  full_name: string;
  is_admin: boolean;
  created_at?: string;
};

export type KeyItem = {
  id: number;
  name: string;
  value: string;
  description: string;
  created_at: string;
};

export type TerminalItem = {
  id: number;
  serial_number: string;
  name: string;
  address: string;
  is_active: boolean;
  created_at: string;
};

export type CardItem = {
  id: number;
  card_number: string;
  owner_name: string;
  balance: number;
  is_blocked: boolean;
  key_id: number;
  created_at: string;
};

export type TransactionItem = {
  id: number;
  amount: number;
  card_id: number;
  terminal_id: number;
  authorized: boolean;
  created_at: string;
};

export type LoginResponse = {
  token: string;
  user: User;
};

export type ApiError = {
  error?: string;
};

export type UserForm = {
  login: string;
  full_name: string;
  password: string;
  is_admin: boolean;
};

export type TerminalForm = {
  serial_number: string;
  name: string;
  address: string;
  is_active: boolean;
};

export type CardForm = {
  card_number: string;
  owner_name: string;
  balance: string;
  is_blocked: boolean;
  key_id: string;
};

export type KeyForm = {
  name: string;
  value: string;
  description: string;
};

export type TerminalToolsForm = {
  card_number: string;
  amount: string;
  terminal_serial_number: string;
};
