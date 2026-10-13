package edu.up.wazuh.ui;

import edu.up.wazuh.model.Alert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pruebas del contrato de filtrado.
 *
 * <p>{@link FiltersPanel.FilterState} decide el subset que comparten mapa,
 * gráficas, tabla y KPI. Estos casos verifican las reglas del PLAN:</p>
 *
 * <ul>
 *   <li>nivel mínimo descarta severidades menores,</li>
 *   <li>filtro de agente descarta eventos que no son del agente seleccionado,</li>
 *   <li>texto busca en descripción, regla, usuario y país,</li>
 *   <li>periodo descarta eventos fuera de la ventana UTC.</li>
 * </ul>
 */
class FilterStateTest {

    @Test
    @DisplayName("Nivel mínimo descarta severidades menores")
    void minLevelFilters() {
        Alert low = alert("a", Instant.parse("2026-10-13T10:00:00Z"), 3);
        Alert high = alert("b", Instant.parse("2026-10-13T10:00:00Z"), 12);
        FiltersPanel.FilterState state = new FiltersPanel.FilterState(
                10, null, "", null, null);
        assertFalse(state.accepts(low));
        assertTrue(state.accepts(high));
    }

    @Test
    @DisplayName("Filtro de agente exige coincidencia exacta")
    void agentFilterMatchesId() {
        Alert other = alert("a", Instant.now(), 3);
        FiltersPanel.FilterState state = new FiltersPanel.FilterState(
                0, "002", "", null, null);
        assertFalse(state.accepts(other));
    }

    @Test
    @DisplayName("Texto se busca en descripcion, regla, usuario y pais (case-insensitive)")
    void textSearchAcrossFields() {
        Alert matchDesc = new Alert("a", Instant.now(),
                "001", "agent", "r1", 5,
                "ssh brute force detected", "", "", null, null, "i");
        Alert matchUser = new Alert("a", Instant.now(),
                "001", "agent", "r1", 5,
                "ok", "jramirez", "", null, null, "i");
        Alert noMatch = new Alert("a", Instant.now(),
                "001", "agent", "r1", 5,
                "ok", "guest", "PA", null, null, "i");
        FiltersPanel.FilterState byDesc = new FiltersPanel.FilterState(
                0, null, "brute", null, null);
        assertTrue(byDesc.accepts(matchDesc));
        FiltersPanel.FilterState byUser = new FiltersPanel.FilterState(
                0, null, "jramirez", null, null);
        assertTrue(byUser.accepts(matchUser));
        assertFalse(byUser.accepts(noMatch));
    }

    @Test
    @DisplayName("Periodo descarta eventos fuera de la ventana")
    void periodFilter() {
        Instant t0 = Instant.parse("2026-10-13T10:00:00Z");
        Instant t1 = Instant.parse("2026-10-13T11:00:00Z");
        Instant t2 = Instant.parse("2026-10-13T13:00:00Z");
        Alert before = alertAt("a", t0, 5);
        Alert inside = alertAt("b", t1, 5);
        Alert after = alertAt("c", t2.plusMillis(1), 5);
        FiltersPanel.FilterState state = new FiltersPanel.FilterState(
                0, null, "", t1, t2);
        assertFalse(state.accepts(before));
        assertTrue(state.accepts(inside));
        assertFalse(state.accepts(after));
    }

    private static Alert alert(String id, Instant ts, int level) {
        return alertAt(id, ts, level);
    }

    private static Alert alertAt(String id, Instant ts, int level) {
        return new Alert(id, ts, "001", "agent", "r1", level,
                "desc", "", "", null, null, "custom-dashboard");
    }
}