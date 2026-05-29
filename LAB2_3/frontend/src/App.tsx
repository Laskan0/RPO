import { FormEvent, useEffect, useMemo, useState } from "react";

import { DashboardPage } from "./pages/DashboardPage";
import { CardsPage } from "./pages/CardsPage";
import { KeysPage } from "./pages/KeysPage";
import { LoginPage } from "./pages/LoginPage";
import { TerminalToolsPage } from "./pages/TerminalToolsPage";
import { TerminalsPage } from "./pages/TerminalsPage";
import { TransactionsPage } from "./pages/TransactionsPage";
import { UsersPage } from "./pages/UsersPage";
import {
  ApiError,
  CardForm,
  CardItem,
  KeyForm,
  KeyItem,
  LoginResponse,
  TerminalForm,
  TerminalItem,
  TerminalToolsForm,
  TransactionItem,
  User,
  UserForm,
  ViewKey,
} from "./types";
import {
  apiBase,
  navItems,
  readViewFromHash,
  subtitleForView,
  titleForView,
  toErrorMessage,
  validateCardForm,
  validateKeyForm,
  validateTerminalForm,
  validateTerminalTools,
  validateUserForm,
} from "./utils";

const emptyUserForm: UserForm = {
  login: "",
  full_name: "",
  password: "",
  is_admin: false,
};

const emptyTerminalForm: TerminalForm = {
  serial_number: "",
  name: "",
  address: "",
  is_active: true,
};

const emptyKeyForm: KeyForm = {
  name: "",
  value: "",
  description: "",
};

const emptyTerminalTools: TerminalToolsForm = {
  card_number: "",
  amount: "100",
  terminal_serial_number: "",
};

function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("auth_token"));
  const [currentUser, setCurrentUser] = useState<User | null>(() => {
    const saved = localStorage.getItem("auth_user");
    if (!saved) {
      return null;
    }

    try {
      return JSON.parse(saved) as User;
    } catch {
      localStorage.removeItem("auth_user");
      return null;
    }
  });
  const [login, setLogin] = useState("admin");
  const [password, setPassword] = useState("password");
  const [loginError, setLoginError] = useState("");
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<ViewKey>(() => readViewFromHash());

  const [users, setUsers] = useState<User[]>([]);
  const [terminals, setTerminals] = useState<TerminalItem[]>([]);
  const [cards, setCards] = useState<CardItem[]>([]);
  const [keys, setKeys] = useState<KeyItem[]>([]);
  const [transactions, setTransactions] = useState<TransactionItem[]>([]);

  const [pageError, setPageError] = useState("");
  const [pageMessage, setPageMessage] = useState("");
  const [loadingPage, setLoadingPage] = useState(false);

  const [editingUserId, setEditingUserId] = useState<number | null>(null);
  const [editingTerminalId, setEditingTerminalId] = useState<number | null>(null);
  const [editingCardId, setEditingCardId] = useState<number | null>(null);
  const [editingKeyId, setEditingKeyId] = useState<number | null>(null);

  const [userForm, setUserForm] = useState<UserForm>(emptyUserForm);
  const [terminalForm, setTerminalForm] = useState<TerminalForm>(emptyTerminalForm);
  const [cardForm, setCardForm] = useState<CardForm>({
    card_number: "",
    owner_name: "",
    balance: "0",
    is_blocked: false,
    key_id: "",
  });
  const [keyForm, setKeyForm] = useState<KeyForm>(emptyKeyForm);
  const [terminalTools, setTerminalTools] = useState<TerminalToolsForm>(emptyTerminalTools);
  const [terminalToolsResult, setTerminalToolsResult] = useState("");
  const [keysLoadResult, setKeysLoadResult] = useState("");

  const isAdmin = currentUser?.is_admin ?? false;
  const dashboardStats = useMemo(
    () => [
      { label: "Пользователи", value: users.length.toString().padStart(2, "0") },
      { label: "Терминалы", value: terminals.length.toString().padStart(2, "0") },
      { label: "Карты", value: cards.length.toString().padStart(2, "0") },
      { label: "Транзакции", value: transactions.length.toString().padStart(2, "0") },
    ],
    [cards.length, terminals.length, transactions.length, users.length],
  );

  useEffect(() => {
    const onHashChange = () => setView(readViewFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    if (token && currentUser) {
      void loadForView(view);
    }
  }, [view, token, currentUser]);

  useEffect(() => {
    if (editingTerminalId !== null && !terminals.some((item) => item.id === editingTerminalId)) {
      setEditingTerminalId(null);
      setTerminalForm(emptyTerminalForm);
    }
  }, [editingTerminalId, terminals]);

  useEffect(() => {
    if (editingCardId !== null && !cards.some((item) => item.id === editingCardId)) {
      resetCardForm([]);
    }
  }, [cards, editingCardId]);

  useEffect(() => {
    if (editingKeyId !== null && !keys.some((item) => item.id === editingKeyId)) {
      setEditingKeyId(null);
      setKeyForm(emptyKeyForm);
    }
  }, [editingKeyId, keys]);

  useEffect(() => {
    setCardForm((current) => {
      if (!current.key_id) {
        return current;
      }

      const exists = keys.some((item) => String(item.id) === current.key_id);
      if (exists) {
        return current;
      }

      return {
        ...current,
        key_id: keys[0] ? String(keys[0].id) : "",
      };
    });
  }, [keys]);

  async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${apiBase}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(init?.headers ?? {}),
      },
    });

    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        const body = (await response.json()) as ApiError;
        if (body.error) {
          message = body.error;
        }
      } catch {
        const text = await response.text();
        if (text) {
          message = text;
        }
      }

      if (response.status === 401) {
        clearSession();
      }

      throw new Error(message);
    }

    return (await response.json()) as T;
  }

  async function apiListRequest<T>(path: string, init?: RequestInit): Promise<T[]> {
    const payload = await apiRequest<T[] | null>(path, init);
    return Array.isArray(payload) ? payload : [];
  }

  async function loadForView(nextView: ViewKey) {
    if (!token || !currentUser) {
      return;
    }

    setPageError("");
    setPageMessage("");
    setLoadingPage(true);

    try {
      if (nextView === "dashboard") {
        const [usersData, terminalsData, cardsData, transactionsData] = await Promise.all([
          apiListRequest<User>("/users"),
          apiListRequest<TerminalItem>("/terminals"),
          apiListRequest<CardItem>("/cards"),
          apiListRequest<TransactionItem>("/transactions"),
        ]);

        setUsers(usersData);
        setTerminals(terminalsData);
        setCards(cardsData);
        setTransactions(transactionsData);
      }

      if (nextView === "users") {
        setUsers(await apiListRequest<User>("/users"));
      }

      if (nextView === "terminals") {
        setTerminals(await apiListRequest<TerminalItem>("/terminals"));
      }

      if (nextView === "cards") {
        const [cardsData, keysData] = await Promise.all([
          apiListRequest<CardItem>("/cards"),
          apiListRequest<KeyItem>("/keys"),
        ]);
        setCards(cardsData);
        setKeys(keysData);
      }

      if (nextView === "keys") {
        setKeys(await apiListRequest<KeyItem>("/keys"));
      }

      if (nextView === "transactions") {
        setTransactions(await apiListRequest<TransactionItem>("/transactions"));
      }

      if (nextView === "terminal" && isAdmin) {
        setTerminals(await apiListRequest<TerminalItem>("/terminals"));
      }
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setLoadingPage(false);
    }
  }

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setLoginError("");

    try {
      const response = await fetch(`${apiBase}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ login, password }),
      });

      if (!response.ok) {
        throw new Error("Неверный логин или пароль.");
      }

      const data = (await response.json()) as LoginResponse;
      const bootstrapResponse = await fetch(`${apiBase}/users`, {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${data.token}`,
        },
      });

      if (!bootstrapResponse.ok) {
        throw new Error("Не удалось загрузить профиль после входа.");
      }

      const bootstrapPayload = (await bootstrapResponse.json()) as User[] | null;
      const bootstrapUsers = Array.isArray(bootstrapPayload) ? bootstrapPayload : [];
      const resolvedUser = bootstrapUsers.find((item) => item.id === data.user.id) ?? data.user;

      window.location.hash = "#dashboard";
      setView("dashboard");
      localStorage.setItem("auth_token", data.token);
      localStorage.setItem("auth_user", JSON.stringify(resolvedUser));
      setToken(data.token);
      setCurrentUser(resolvedUser);
    } catch (error) {
      setLoginError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  function clearSession() {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_user");
    setToken(null);
    setCurrentUser(null);
    setUsers([]);
    setTerminals([]);
    setCards([]);
    setKeys([]);
    setTransactions([]);
    setPageError("");
    setPageMessage("");
    window.location.hash = "";
  }

  async function saveUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setPageError("");

    try {
      const userValidationError = validateUserForm(userForm, editingUserId !== null);
      if (userValidationError) {
        throw new Error(userValidationError);
      }

      const method = editingUserId ? "PUT" : "POST";
      const path = editingUserId ? `/users/${editingUserId}` : "/users";
      await apiRequest<User>(path, {
        method,
        body: JSON.stringify(userForm),
      });

      setUserForm(emptyUserForm);
      setEditingUserId(null);
      setPageMessage(editingUserId ? "Пользователь обновлён." : "Пользователь создан.");
      setUsers(await apiListRequest<User>("/users"));
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function deleteUser(id: number) {
    if (!confirm("Удалить пользователя?")) {
      return;
    }

    setBusy(true);
    setPageError("");
    try {
      await apiRequest<{ status: string }>(`/users/${id}`, { method: "DELETE" });
      if (currentUser && id === currentUser.id) {
        clearSession();
        return;
      }
      setUsers(await apiListRequest<User>("/users"));
      setPageMessage("Пользователь удалён.");
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function saveTerminal(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setPageError("");

    try {
      const terminalValidationError = validateTerminalForm(terminalForm);
      if (terminalValidationError) {
        throw new Error(terminalValidationError);
      }

      const method = editingTerminalId ? "PUT" : "POST";
      const path = editingTerminalId ? `/terminals/${editingTerminalId}` : "/terminals";
      await apiRequest<TerminalItem>(path, {
        method,
        body: JSON.stringify(terminalForm),
      });
      setTerminalForm(emptyTerminalForm);
      setEditingTerminalId(null);
      setTerminals(await apiListRequest<TerminalItem>("/terminals"));
      setPageMessage(editingTerminalId ? "Терминал обновлён." : "Терминал создан.");
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function deleteTerminal(id: number) {
    if (!confirm("Удалить терминал?")) {
      return;
    }

    setBusy(true);
    setPageError("");
    try {
      await apiRequest<{ status: string }>(`/terminals/${id}`, { method: "DELETE" });
      if (editingTerminalId === id) {
        setEditingTerminalId(null);
        setTerminalForm(emptyTerminalForm);
      }
      setTerminals(await apiListRequest<TerminalItem>("/terminals"));
      setPageMessage("Терминал удалён.");
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function saveCard(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setPageError("");

    try {
      const cardValidationError = validateCardForm(cardForm);
      if (cardValidationError) {
        throw new Error(cardValidationError);
      }

      const payload = {
        card_number: cardForm.card_number,
        owner_name: cardForm.owner_name,
        balance: Number(cardForm.balance),
        is_blocked: cardForm.is_blocked,
        key_id: Number(cardForm.key_id),
      };
      const method = editingCardId ? "PUT" : "POST";
      const path = editingCardId ? `/cards/${editingCardId}` : "/cards";
      await apiRequest<CardItem>(path, {
        method,
        body: JSON.stringify(payload),
      });
      resetCardForm();
      const [cardsData, keysData] = await Promise.all([
        apiListRequest<CardItem>("/cards"),
        apiListRequest<KeyItem>("/keys"),
      ]);
      setCards(cardsData);
      setKeys(keysData);
      setPageMessage(editingCardId ? "Карта обновлена." : "Карта создана.");
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function deleteCard(id: number) {
    if (!confirm("Удалить карту?")) {
      return;
    }

    setBusy(true);
    setPageError("");
    try {
      await apiRequest<{ status: string }>(`/cards/${id}`, { method: "DELETE" });
      if (editingCardId === id) {
        resetCardForm(keys);
      }
      setCards(await apiListRequest<CardItem>("/cards"));
      setPageMessage("Карта удалена.");
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function saveKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setPageError("");

    try {
      const keyValidationError = validateKeyForm(keyForm);
      if (keyValidationError) {
        throw new Error(keyValidationError);
      }

      const method = editingKeyId ? "PUT" : "POST";
      const path = editingKeyId ? `/keys/${editingKeyId}` : "/keys";
      await apiRequest<KeyItem>(path, {
        method,
        body: JSON.stringify(keyForm),
      });
      setKeyForm(emptyKeyForm);
      setEditingKeyId(null);
      setKeys(await apiListRequest<KeyItem>("/keys"));
      setPageMessage(editingKeyId ? "Ключ обновлён." : "Ключ создан.");
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function deleteKey(id: number) {
    if (!confirm("Удалить ключ?")) {
      return;
    }

    setBusy(true);
    setPageError("");
    try {
      await apiRequest<{ status: string }>(`/keys/${id}`, { method: "DELETE" });
      if (editingKeyId === id) {
        setEditingKeyId(null);
        setKeyForm(emptyKeyForm);
      }
      setKeys(await apiListRequest<KeyItem>("/keys"));
      setPageMessage("Ключ удалён.");
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function refreshTransactions() {
    setBusy(true);
    setPageError("");
    try {
      setTransactions(await apiListRequest<TransactionItem>("/transactions"));
      setPageMessage("Список транзакций обновлён.");
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function authorizePayment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setPageError("");
    setTerminalToolsResult("");

    try {
      const authorizeValidationError = validateTerminalTools(terminalTools);
      if (authorizeValidationError) {
        throw new Error(authorizeValidationError);
      }

      const result = await apiRequest<{
        authorized: boolean;
        message: string;
        transaction: TransactionItem;
      }>("/terminal/authorize", {
        method: "POST",
        body: JSON.stringify({
          card_number: terminalTools.card_number,
          amount: Number(terminalTools.amount),
          terminal_serial_number: terminalTools.terminal_serial_number,
        }),
      });

      setTerminalToolsResult(
        result.authorized
          ? `Транзакция разрешена. ID: ${result.transaction.id}, сообщение: ${result.message}.`
          : `Транзакция отклонена: ${result.message}.`,
      );
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function loadTerminalKeys() {
    if (!terminalTools.terminal_serial_number) {
      setPageError("Введите серийный номер терминала.");
      return;
    }

    setBusy(true);
    setPageError("");
    setKeysLoadResult("");

    try {
      const result = await apiRequest<{ terminal: TerminalItem; keys: KeyItem[] }>(
        `/terminal/keys?terminal_serial_number=${encodeURIComponent(terminalTools.terminal_serial_number)}`,
      );
      setKeysLoadResult(
        `Для терминала ${result.terminal.name} доступно ключей: ${result.keys.length}.`,
      );
    } catch (error) {
      setPageError(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  function beginUserEdit(item: User) {
    setEditingUserId(item.id);
    setUserForm({
      login: item.login,
      full_name: item.full_name,
      password: "",
      is_admin: item.is_admin,
    });
  }

  function beginTerminalEdit(item: TerminalItem) {
    setEditingTerminalId(item.id);
    setTerminalForm({
      serial_number: item.serial_number,
      name: item.name,
      address: item.address,
      is_active: item.is_active,
    });
  }

  function beginCardEdit(item: CardItem) {
    setEditingCardId(item.id);
    setCardForm({
      card_number: item.card_number,
      owner_name: item.owner_name,
      balance: String(item.balance),
      is_blocked: item.is_blocked,
      key_id: String(item.key_id),
    });
  }

  function beginKeyEdit(item: KeyItem) {
    setEditingKeyId(item.id);
    setKeyForm({
      name: item.name,
      value: item.value,
      description: item.description,
    });
  }

  function resetCardForm(nextKeys: KeyItem[] = keys) {
    setEditingCardId(null);
    setCardForm({
      card_number: "",
      owner_name: "",
      balance: "0",
      is_blocked: false,
      key_id: nextKeys[0] ? String(nextKeys[0].id) : "",
    });
  }

  function renderView() {
    switch (view) {
      case "dashboard":
        return <DashboardPage stats={dashboardStats} />;
      case "users":
        return (
          <UsersPage
            busy={busy}
            editingUserId={editingUserId}
            isAdmin={isAdmin}
            onCancelEdit={() => {
              setEditingUserId(null);
              setUserForm(emptyUserForm);
            }}
            onDeleteUser={deleteUser}
            onEditUser={beginUserEdit}
            onSubmit={saveUser}
            setUserForm={setUserForm}
            userForm={userForm}
            users={users}
          />
        );
      case "terminals":
        return (
          <TerminalsPage
            busy={busy}
            editingTerminalId={editingTerminalId}
            isAdmin={isAdmin}
            onDeleteTerminal={deleteTerminal}
            onEditTerminal={beginTerminalEdit}
            onSubmit={saveTerminal}
            setTerminalForm={setTerminalForm}
            terminalForm={terminalForm}
            terminals={terminals}
          />
        );
      case "cards":
        return (
          <CardsPage
            busy={busy}
            cardForm={cardForm}
            cards={cards}
            editingCardId={editingCardId}
            isAdmin={isAdmin}
            keys={keys}
            onCancelEdit={() => resetCardForm()}
            onDeleteCard={deleteCard}
            onEditCard={beginCardEdit}
            onSubmit={saveCard}
            setCardForm={setCardForm}
          />
        );
      case "keys":
        return (
          <KeysPage
            busy={busy}
            editingKeyId={editingKeyId}
            isAdmin={isAdmin}
            keyForm={keyForm}
            keys={keys}
            onDeleteKey={deleteKey}
            onEditKey={beginKeyEdit}
            onSubmit={saveKey}
            setKeyForm={setKeyForm}
          />
        );
      case "transactions":
        return (
          <TransactionsPage
            isAdmin={isAdmin}
            onRefresh={refreshTransactions}
            transactions={transactions}
          />
        );
      case "terminal":
        return (
          <TerminalToolsPage
            busy={busy}
            keysLoadResult={keysLoadResult}
            onLoadKeys={loadTerminalKeys}
            onSubmit={authorizePayment}
            setTerminalTools={setTerminalTools}
            terminalTools={terminalTools}
            terminalToolsResult={terminalToolsResult}
          />
        );
    }
  }

  if (!token || !currentUser) {
    return (
      <LoginPage
        busy={busy}
        login={login}
        loginError={loginError}
        onLoginChange={setLogin}
        onPasswordChange={setPassword}
        onSubmit={handleLogin}
        password={password}
      />
    );
  }

  return (
    <div className="shell">
      <div className="ambient ambient-left" />
      <div className="ambient ambient-right" />
      <header className="topbar" />

      <div className="workspace">
        <aside className="sidebar">
          <div>
            <p className="eyebrow">React Frontend</p>
            <h2 className="sidebar-title">Payment Auth Admin</h2>
          </div>

          <div className="profile-card">
            <strong>{currentUser.login}</strong>
            <span>{currentUser.is_admin ? "Администратор" : "Обычный пользователь"}</span>
          </div>

          <nav className="nav-list">
            {navItems.map((item) => (
              <button
                key={item.key}
                className={item.key === view ? "nav-item active" : "nav-item"}
                onClick={() => {
                  window.location.hash = item.key;
                }}
                type="button"
              >
                {item.label}
              </button>
            ))}
          </nav>

          <button className="ghost-button" type="button" onClick={clearSession}>
            Выйти
          </button>
        </aside>

        <main className="content">
          <section className="hero-card">
            <div>
              <p className="eyebrow">Transport Control Panel</p>
              <h1>{titleForView(view)}</h1>
              <p className="muted">{subtitleForView(view)}</p>
            </div>
            <div className="hero-badge">
              <span>{isAdmin ? "admin" : "user"}</span>
            </div>
          </section>

          {pageError ? <div className="banner danger">{pageError}</div> : null}
          {pageMessage ? <div className="banner success">{pageMessage}</div> : null}
          {loadingPage ? <div className="banner info">Загружаю данные...</div> : null}

          {renderView()}
        </main>
      </div>
    </div>
  );
}

export default App;
