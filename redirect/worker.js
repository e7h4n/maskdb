// Apex → www redirect. maskdb.ai/* → https://www.maskdb.ai/* (301, path+query preserved).
export default {
  fetch(req) {
    const url = new URL(req.url);
    url.protocol = "https:";
    url.hostname = "www.maskdb.ai";
    return Response.redirect(url.toString(), 301);
  },
};
