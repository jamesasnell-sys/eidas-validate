package com.provlyn.eidasvalidate.api;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ReadListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Rejects request bodies larger than a validation request could legitimately
 * need.
 *
 * <p>A DER-encoded RFC 3161 token is a few kilobytes; base64 adds a third.
 * Nothing genuine comes close to the cap here. The limit exists because
 * several of the parsing faults fixed in recent BouncyCastle releases were
 * unbounded allocations driven by lengths declared in the input itself, and a
 * size ceiling blunts that whole class of attack regardless of which library
 * version is underneath.
 *
 * <p>Neither Tomcat's form-post limit nor Spring's codec limit applies to a
 * JSON body in a servlet application, so without this the only thing standing
 * between the service and a very large payload is Jackson's default string
 * cap, which is measured in tens of megabytes and was never chosen for this
 * purpose.
 *
 * <p>Content-Length is checked first because it is free, but it is not
 * trusted on its own: it is absent on a chunked request and can be understated.
 * The stream is therefore also counted as it is read, and cut off at the same
 * ceiling.
 */
public class RequestSizeFilter extends OncePerRequestFilter {

    private static final String LIMITED_PATH_PREFIX = "/api/";

    private final int maxBytes;

    public RequestSizeFilter(int maxBytes) {
        this.maxBytes = maxBytes;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith(LIMITED_PATH_PREFIX);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (request.getContentLengthLong() > maxBytes) {
            reject(response);
            return;
        }

        try {
            chain.doFilter(new LimitedRequest(request, maxBytes), response);
        } catch (BodyTooLargeException e) {
            if (!response.isCommitted()) {
                reject(response);
            }
        }
    }

    private void reject(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.PAYLOAD_TOO_LARGE.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(
                "{\"error\":\"Request body too large. A timestamp token is a few "
                        + "kilobytes; this endpoint accepts at most " + (maxBytes / 1024)
                        + " KB. Send the token and a digest, never the document.\"}");
    }

    /** Signals that the body exceeded the ceiling partway through reading. */
    static final class BodyTooLargeException extends RuntimeException {
        BodyTooLargeException() {
            super(null, null, false, false);
        }
    }

    private static final class LimitedRequest extends HttpServletRequestWrapper {

        private final int maxBytes;

        LimitedRequest(HttpServletRequest request, int maxBytes) {
            super(request);
            this.maxBytes = maxBytes;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            ServletInputStream delegate = super.getInputStream();
            return new ServletInputStream() {

                private long count;

                private void count(int read) {
                    if (read > 0) {
                        count += read;
                        if (count > maxBytes) {
                            throw new BodyTooLargeException();
                        }
                    }
                }

                @Override
                public int read() throws IOException {
                    int b = delegate.read();
                    count(b >= 0 ? 1 : 0);
                    return b;
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    int read = delegate.read(b, off, len);
                    count(read);
                    return read;
                }

                @Override
                public boolean isFinished() {
                    return delegate.isFinished();
                }

                @Override
                public boolean isReady() {
                    return delegate.isReady();
                }

                @Override
                public void setReadListener(ReadListener readListener) {
                    delegate.setReadListener(readListener);
                }
            };
        }
    }
}
