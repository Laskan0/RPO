type DashboardPageProps = {
  stats: Array<{ label: string; value: string }>;
};

export function DashboardPage(props: DashboardPageProps) {
  return (
    <section className="stat-grid">
      {props.stats.map((item) => (
        <article className="panel stat-card" key={item.label}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
        </article>
      ))}
    </section>
  );
}
