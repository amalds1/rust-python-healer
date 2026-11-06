CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  uri TEXT NOT NULL,
  title TEXT NOT NULL,
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  python_constraint TEXT NOT NULL,
  content TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(source, uri, version)
);
CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
  title, package, content,
  content='documents', content_rowid='id', tokenize='unicode61'
);
CREATE TRIGGER IF NOT EXISTS docs_ai AFTER INSERT ON documents BEGIN
  INSERT INTO documents_fts(rowid,title,package,content)
  VALUES(new.id,new.title,new.package,new.content);
END;
CREATE TRIGGER IF NOT EXISTS docs_ad AFTER DELETE ON documents BEGIN
  INSERT INTO documents_fts(documents_fts,rowid,title,package,content)
  VALUES('delete',old.id,old.title,old.package,old.content);
END;
CREATE TRIGGER IF NOT EXISTS docs_au AFTER UPDATE ON documents BEGIN
  INSERT INTO documents_fts(documents_fts,rowid,title,package,content)
  VALUES('delete',old.id,old.title,old.package,old.content);
  INSERT INTO documents_fts(rowid,title,package,content)
  VALUES(new.id,new.title,new.package,new.content);
END;

