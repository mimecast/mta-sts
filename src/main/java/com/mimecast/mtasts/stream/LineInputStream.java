package com.mimecast.mtasts.stream;

import java.io.*;

/**
 * Line input stream.
 */
public class LineInputStream implements Closeable {

    /**
     * Line Feed.
     */
    public static final int LF = 10; // \n

    /**
     * Carriage Return.
     */
    public static final int CR = 13; // \r

    /**
     * Input stream wrapper used to unread.
     */
    private final PushbackInputStream inputStream;

    /**
     * Buffer used for reading.
     * <p>This buffer is instantiated only once in this class for performance.
     * <p>The reference to it should not escape this class.
     */
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(1024);

    /**
     * Constructs new instance from provided input stream.
     *
     * @param stream Input stream.
     */
    public LineInputStream(InputStream stream) {
        inputStream = new PushbackInputStream(stream);
    }

    /**
     * Reads one line and returns it as a ByteArrayOutputStream.
     *
     * @return OutputStream containing read line.
     * @throws IOException Stream closed.
     */
    @SuppressWarnings("squid:S1168")
    public byte[] readLine() throws IOException {
        buffer.reset(); // Clear buffer without reallocating memory.
        if (readLineToBuffer()) {
            return buffer.toByteArray();
        }

        if (buffer.size() == 0) {
            return null;
        }

        return buffer.toByteArray();
    }

    /**
     * Reads bytes until it finds an acceptable line ending.
     *
     * @return Boolean.
     * @throws IOException Stream was closed.
     */
    private boolean readLineToBuffer() throws IOException {
        int prevChar = ' ';
        int intCh;
        while ((intCh = inputStream.read()) != -1) {
            boolean eol = false;

            if (intCh == CR && prevChar == LF) {
                eol = true;
            }
            else if (intCh == LF && prevChar == CR) {
                eol = true;
            }
            else if (prevChar == CR || prevChar == LF) {
                inputStream.unread(intCh);
                return true;
            }

            prevChar = intCh;
            buffer.write(intCh);
            if (eol) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void close() throws IOException {
        buffer.close();
        inputStream.close();
    }
}
