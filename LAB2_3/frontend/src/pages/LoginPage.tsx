import { FormEvent } from "react";

type LoginPageProps = {
  busy: boolean;
  login: string;
  loginError: string;
  password: string;
  onLoginChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
};

export function LoginPage(props: LoginPageProps) {
  return (
    <div className="shell">
      <div className="ambient ambient-left" />
      <div className="ambient ambient-right" />
      <main className="login-layout">
        <section className="login-copy">
          <p className="eyebrow"> Transport Console</p>
          <h1></h1>
          
        </section>

        <section className="panel login-panel">
          <p className="eyebrow">JWT Login</p>
          <h2>Вход в панель управления</h2>
          <p className="muted">
            Используйте логин и пароль из seed-данных или вашей локальной базы.
          </p>

          <form className="stack" onSubmit={props.onSubmit}>
            <label className="field">
              <span>Логин</span>
              <input value={props.login} onChange={(event) => props.onLoginChange(event.target.value)} />
            </label>
            <label className="field">
              <span>Пароль</span>
              <input
                type="password"
                value={props.password}
                onChange={(event) => props.onPasswordChange(event.target.value)}
              />
            </label>

            {props.loginError ? <div className="banner danger">{props.loginError}</div> : null}

            <button className="primary-button" type="submit" disabled={props.busy}>
              {props.busy ? "Входим..." : "Войти"}
            </button>
          </form>
        </section>
      </main>
    </div>
  );
}
