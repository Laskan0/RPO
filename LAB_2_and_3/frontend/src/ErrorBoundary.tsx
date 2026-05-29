import { Component, ErrorInfo, ReactNode } from "react";

type Props = {
  children: ReactNode;
};

type State = {
  hasError: boolean;
};

class ErrorBoundary extends Component<Props, State> {
  state: State = {
    hasError: false,
  };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("frontend render error", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="shell">
          <div className="ambient ambient-left" />
          <div className="ambient ambient-right" />
          <main className="login-layout">
            <section className="panel login-panel">
              <p className="eyebrow">Frontend Error</p>
              <h2>Интерфейс столкнулся с ошибкой</h2>
              <p className="muted">
                Обновите страницу. Если ошибка повторится, выйдите из аккаунта
                через очистку localStorage для этого сайта.
              </p>
            </section>
          </main>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
