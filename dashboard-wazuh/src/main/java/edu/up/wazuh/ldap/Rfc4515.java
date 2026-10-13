package edu.up.wazuh.ldap;

/**
 * Escapes values for use inside an LDAP search filter as defined by
 * RFC 4515 §3. The characters {@code \\} (0x5C), {@code *} (0x2A),
 * {@code (} (0x28), {@code )} (0x29), and the NUL byte (0x00) receive the
 * two-character hex escape form.
 */
public final class Rfc4515 {

    private Rfc4515() {
    }

    public static String escape(String value) {
        if (value == null) return "";
        StringBuilder sb = new StringBuilder(value.length() + 4);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\0':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}
