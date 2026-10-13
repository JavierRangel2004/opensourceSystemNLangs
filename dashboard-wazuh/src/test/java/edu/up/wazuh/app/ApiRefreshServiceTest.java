package edu.up.wazuh.app;

import edu.up.wazuh.api.WazuhApiClient;
import edu.up.wazuh.model.Agent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiRefreshServiceTest {

    private ApiRefreshService svc;

    @AfterEach
    void cleanup() {
        if (svc != null) svc.close();
    }


    @Test
    void tickRealReportaEstadoErrorSinFiltrarDetalle() throws Exception {
        WazuhApiClient failing = new WazuhApiClient(URI.create("http://127.0.0.1:1"), "u", "p") {
            @Override
            public List<Agent> fetchAgents() throws IOException {
                throw new IOException("credenciales secretas leak");
            }
        };
        svc = new ApiRefreshService(failing, 50L, "api");
        svc.tick();
        String msg = svc.current().status;
        assertTrue(msg.startsWith("error:"), "Debe etiquetar el error: " + msg);
        assertFalse(msg.contains("credenciales secretas"),
                "El estado no debe filtrar el mensaje de la excepción: " + msg);
        assertFalse(msg.contains("u:p"), "El estado no debe contener credenciales: " + msg);
        assertFalse(msg.contains("127.0.0.1:1"), "El estado no debe exponer la URL completa: " + msg);
        assertTrue(svc.current().agents.isEmpty());
    }

}