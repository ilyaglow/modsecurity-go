package modsecurity

import (
	"io"
	"net/http"
)

type requestBodyReader struct {
	io.ReadCloser
	connection *connection
}

type responseWriter struct {
	http.ResponseWriter
	connection *connection
}

func (c *connection) getRequestBodyReader() io.ReadCloser {
	return &requestBodyReader{
		ReadCloser: c.request.Body,
		connection: c,
	}
}

func (c *connection) getResponseWriter() http.ResponseWriter {
	return &responseWriter{
		ResponseWriter: c.responseWriter,
		connection:     c,
	}
}

func (r *requestBodyReader) Read(p []byte) (int, error) {
	if r.connection.intervention != nil {
		return 0, io.EOF
	}
	readed, error := r.ReadCloser.Read(p)
	if readed > 0 {
		r.connection.trans.AppendRequestBody(p)
		r.connection.intervention = r.connection.trans.Intervention()
		if r.connection.intervention != nil {
			return 0, io.EOF
		}
	}
	return readed, error
}

func (r *responseWriter) Write(p []byte) (int, error) {
	if r.connection.intervention != nil {
		return 0, io.EOF
	}

	r.connection.trans.AppendResponseBody(p)
	r.connection.intervention = r.connection.trans.Intervention()
	if r.connection.intervention != nil {
		return 0, io.EOF
	}

	return r.ResponseWriter.Write(p)

}
