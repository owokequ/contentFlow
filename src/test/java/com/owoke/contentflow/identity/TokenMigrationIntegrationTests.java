package com.owoke.contentflow.identity;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import com.owoke.contentflow.PostgresIntegrationTest;

class TokenMigrationIntegrationTests extends PostgresIntegrationTest {
    @Autowired DataSource dataSource;

    @Test
    void upgradingExistingSchemaRevokesLegacySessionsAndPreservesUsers() {
        String schema = "migration_" + UUID.randomUUID().toString().replace("-", "");
        Flyway.configure().dataSource(dataSource).schemas(schema).defaultSchema(schema).target("4")
                .load().migrate();
        var jdbc = new JdbcTemplate(dataSource);
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        jdbc.update("insert into " + schema + ".users (id, email, password_hash, display_name) values (?, ?, ?, ?)",
                userId, "legacy@example.com", "legacy-hash", "Артём");
        jdbc.update("insert into " + schema + ".auth_sessions (id, user_id, expires_at) "
                + "values (?, ?, current_timestamp + interval '1 day')", sessionId, userId);
        Flyway.configure().dataSource(dataSource).schemas(schema).defaultSchema(schema).target("5")
                .load().migrate();
        assertThat(jdbc.queryForObject("select revoked_at is not null from " + schema
                + ".auth_sessions where id = ?", Boolean.class, sessionId)).isTrue();
        assertThat(jdbc.queryForObject("select client_type from " + schema
                + ".auth_sessions where id = ?", String.class, sessionId)).isEqualTo("API");
        assertThat(jdbc.queryForObject("select count(*) from " + schema + ".users", Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from " + schema + ".refresh_tokens", Long.class)).isZero();
    }
}
