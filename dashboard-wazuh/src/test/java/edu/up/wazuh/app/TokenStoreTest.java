package edu.up.wazuh.app;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenStoreTest {

    @Test
    void generaTokenRuntimeSiNoSeProporciona() {
        TokenStore t = new TokenStore(null);
        assertTrue(t.generatedRuntime(), "Debe marcar generación runtime");
        assertTrue(t.token().length() >= 32, "Token debe tener al menos 32 chars base64url");
    }

    @Test
    void respetaTokenExistente() {
        TokenStore t = new TokenStore("token-externo-1234567890");
        assertFalse(t.generatedRuntime());
        assertEquals("token-externo-1234567890", t.token());
    }

    @Test
    void matchesComparaSinFiltroDeCaseParaBearer() {
        TokenStore t = new TokenStore("abc");
        assertTrue(t.matches("Bearer abc"));
        assertTrue(t.matches("bearer abc"));
        assertTrue(t.matches("  Bearer   abc  "));
        assertFalse(t.matches("Bearer abd"));
        assertFalse(t.matches(null));
        assertFalse(t.matches("Basic abc"));
    }

    @Test
    void rechazaTokenPresentePeroInvalido() {
        TokenStore t = new TokenStore("valor-correcto");
        assertFalse(t.matches(""));
        assertFalse(t.matches("Bearer"));
        assertFalse(t.matches("Bearer "));
        assertFalse(t.matches("Token valor-correcto"));
    }

    @Test
    void toStringNoExponeElToken() {
        TokenStore t = new TokenStore("secreto-privado-1234567890");
        String s = t.toString();
        assertFalse(s.contains("secreto-privado"), "toString no debe filtrar el token");
        assertTrue(s.contains("TokenStore"));
    }
}