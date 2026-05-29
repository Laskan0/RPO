import { FormEvent } from "react";

import { TerminalToolsForm } from "../types";

type TerminalToolsPageProps = {
  busy: boolean;
  keysLoadResult: string;
  onLoadKeys: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  setTerminalTools: React.Dispatch<React.SetStateAction<TerminalToolsForm>>;
  terminalTools: TerminalToolsForm;
  terminalToolsResult: string;
};

export function TerminalToolsPage(props: TerminalToolsPageProps) {
  return (
    <section className="terminal-grid">
      <article className="panel">
        <div className="section-head">
          <h3>Авторизация списания</h3>
          <span>Публичный terminal endpoint</span>
        </div>

        <form className="stack" onSubmit={props.onSubmit}>
          <label className="field">
            <span>Номер карты</span>
            <input
              value={props.terminalTools.card_number}
              onChange={(event) =>
                props.setTerminalTools((current) => ({
                  ...current,
                  card_number: event.target.value,
                }))
              }
            />
          </label>
          <label className="field">
            <span>Сумма</span>
            <input
              type="number"
              value={props.terminalTools.amount}
              onChange={(event) =>
                props.setTerminalTools((current) => ({
                  ...current,
                  amount: event.target.value,
                }))
              }
            />
          </label>
          <label className="field">
            <span>Серийный номер терминала</span>
            <input
              value={props.terminalTools.terminal_serial_number}
              onChange={(event) =>
                props.setTerminalTools((current) => ({
                  ...current,
                  terminal_serial_number: event.target.value,
                }))
              }
            />
          </label>

          <button className="primary-button" type="submit" disabled={props.busy}>
            Проверить транзакцию
          </button>
        </form>

        {props.terminalToolsResult ? <div className="banner success">{props.terminalToolsResult}</div> : null}
      </article>

      <article className="panel">
        <div className="section-head">
          <h3>Загрузка ключей</h3>
          <span />
        </div>
        <button className="primary-button" type="button" onClick={props.onLoadKeys}>
          Получить ключи
        </button>
        {props.keysLoadResult ? <div className="banner info">{props.keysLoadResult}</div> : null}
        {!props.keysLoadResult ? (
          <p className="muted compact">
            Введите серийный номер слева и нажмите кнопку для проверки.
          </p>
        ) : null}
      </article>
    </section>
  );
}
