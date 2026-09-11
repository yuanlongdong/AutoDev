"""v0.7.0 fixtures: Python 2 print-statement syntax + Tornado handlers."""
import tornado.web
import io


class SearchHandler(tornado.web.RequestHandler):

    def get(self):
        print "GET ", self.request.uri
        query = self.get_argument("q", default="Query")
        self.render("search.html", query=query, link=query)


class UploadHandler(tornado.web.RequestHandler):

    def post(self):
        file1 = self.request.files['file1'][0]
        fname = file1['filename']
        out = io.open("/tmp/" + fname, 'wb')
        out.write(file1['body'])
        out.close()


def make_app():
    settings = {"debug": True}
    app = tornado.web.Application([], **settings)
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.bind(7777, address='0.0.0.0')
    return app
