package com.mimecast.mtasts.assets;

import java.util.Optional;

/**
 * Policy modes.
 *
 * @link https://tools.ietf.org/html/rfc8461#section-5 RFC8461#section-5
 */
public enum StsMode {

    /**
     * Mode NONE.
     * <p>No active policy.
     */
    NONE ("none"),

    /**
     * Mode TESTING.
     * <p>Should deliver regardless of validation failures.
     */
    TESTING ("testing"),

    /**
     * Mode ENFORCE.
     * <p>MUST NOT deliver to hosts that fail MX matching or certificate validation or that do not support STARTTLS.
     */
    ENFORCE ("enforce");

    /**
     * Current mode.
     */
    private final String mode;

    /**
     * Constructs new instance.
     *
     * @param mode Mode name string.
     */
    StsMode(String mode) {
        this.mode = mode;
    }

    /**
     * Get mode by name.
     *
     * @param name Mode name string.
     * @return Optional of Modes value.
     */
    public static Optional<StsMode> get(String name) {
        for (StsMode value : StsMode.values()) {
            if (value.mode.equalsIgnoreCase(name)) {
                return Optional.of(value);
            }
        }

        return Optional.empty();
    }

    /**
     * To String.
     *
     * @return String.
     */
    @Override
    public String toString() {
        return this.mode;
    }
}
