/*
    This file is part of Octra Wallet (webcli).

    Octra Wallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Octra Wallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Octra Wallet.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2025-2026 Octra Labs
              2025-2026 David A.
              2025-2026 Alex T.
              2025-2026 Vadim S.
              2025-2026 Julia L.
*/

function idePrompt(title, message, defaultVal) {
  return new Promise(function(resolve) {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay';
    ov.innerHTML = '<div class="modal-box">' +
      '<div class="modal-title">' + title + '</div>' +
      (message ? '<div class="modal-message">' + message + '</div>' : '') +
      '<input class="modal-input" type="text" value="' + (defaultVal || '') + '">' +
      '<div class="modal-buttons">' +
        '<button class="modal-btn" data-action="cancel">cancel</button>' +
        '<button class="modal-btn modal-btn-primary" data-action="ok">ok</button>' +
      '</div></div>';
    document.body.appendChild(ov);
    var inp = ov.querySelector('.modal-input');
    inp.focus(); inp.select();
    inp.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { document.body.removeChild(ov); resolve(inp.value); }
      if (e.key === 'Escape') { document.body.removeChild(ov); resolve(null); }
    });
    ov.addEventListener('click', function(e) {
      var a = e.target.getAttribute('data-action');
      if (a === 'ok') { document.body.removeChild(ov); resolve(inp.value); }
      if (a === 'cancel' || e.target === ov) { document.body.removeChild(ov); resolve(null); }
    });
  });
}
function ideConfirm(title, message) {
  return new Promise(function(resolve) {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay';
    ov.innerHTML = '<div class="modal-box">' +
      '<div class="modal-title">' + title + '</div>' +
      '<div class="modal-message">' + message + '</div>' +
      '<div class="modal-buttons">' +
        '<button class="modal-btn" data-action="cancel">cancel</button>' +
        '<button class="modal-btn modal-btn-primary" data-action="ok">confirm</button>' +
      '</div></div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function(e) {
      var a = e.target.getAttribute('data-action');
      if (a === 'ok') { document.body.removeChild(ov); resolve(true); }
      if (a === 'cancel' || e.target === ov) { document.body.removeChild(ov); resolve(false); }
    });
    ov.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { document.body.removeChild(ov); resolve(true); }
      if (e.key === 'Escape') { document.body.removeChild(ov); resolve(false); }
    });
    ov.focus();
  });
}
function ideMenu(title, options) {
  return new Promise(function(resolve) {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay';
    var btns = options.map(function(o, i) {
      return '<button class="modal-btn" data-idx="' + i + '" style="width:100%;text-align:left;margin-bottom:4px">' + o.label + '</button>';
    }).join('');
    ov.innerHTML = '<div class="modal-box">' +
      '<div class="modal-title">' + title + '</div>' +
      btns +
      '<div class="modal-buttons" style="margin-top:8px">' +
        '<button class="modal-btn" data-action="cancel">cancel</button>' +
      '</div></div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function(e) {
      var idx = e.target.getAttribute('data-idx');
      if (idx !== null) { document.body.removeChild(ov); resolve(options[parseInt(idx)].value); return; }
      if (e.target.getAttribute('data-action') === 'cancel' || e.target === ov) { document.body.removeChild(ov); resolve(null); }
    });
  });
}

var _walletAddr = '';
var _historyOffset = 0;
var _historyLimit = 20;
var _refreshTimer = null;
var _prevView = 'dashboard';
var _cachedBal = null;
var _encryptedBalanceRaw = 0;
var _unclaimedCount = 0;
var _pendingClaimIds = {};
var _explorerUrl = 'https://octrascan.io';
var _tokens = [];
var _selectedToken = null;
var _tokenSymbols = {};
var _tokenDecimals = {};
var _tokensLoaded = false;
var _tokTxGen = 0;
var _compiledAbi = null;
var _fees = {};
var _rpcHost = '';
var _hasMasterSeed = false;


var _ideProject = null;  // { id, name, created, template }
var _ideFiles = {};       // { path: content }
var _ideActiveFile = null;
var _ideOpenTabs = [];
var _ideSaveTimer = null;
var _ideMode = false;     // false=single file, true=project mode

var ProjectStore = (function() {
  var DB_NAME = 'octra_ide';
  var DB_VERSION = 1;
  var db = null;

  function open() {
    return new Promise(function(resolve, reject) {
      if (db) { resolve(db); return; }
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function(e) {
        var d = e.target.result;
        if (!d.objectStoreNames.contains('projects')) {
          d.createObjectStore('projects', { keyPath: 'id' });
        }
        if (!d.objectStoreNames.contains('files')) {
          var fs = d.createObjectStore('files', { keyPath: 'key' });
          fs.createIndex('project', 'project_id', { unique: false });
        }
      };
      req.onsuccess = function(e) { db = e.target.result; resolve(db); };
      req.onerror = function(e) { reject(e.target.error); };
    });
  }

  function tx(stores, mode) {
    return db.transaction(stores, mode);
  }

  return {
    createProject: async function(name, template) {
      await open();
      var id = 'prj_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
      var proj = { id: id, name: name, created: Date.now(), template: template || 'empty' };
      return new Promise(function(resolve, reject) {
        var t = tx(['projects'], 'readwrite');
        t.objectStore('projects').put(proj);
        t.oncomplete = function() { resolve(proj); };
        t.onerror = function(e) { reject(e.target.error); };
      });
    },

    listProjects: async function() {
      await open();
      return new Promise(function(resolve, reject) {
        var t = tx(['projects'], 'readonly');
        var req = t.objectStore('projects').getAll();
        req.onsuccess = function() { resolve(req.result || []); };
        req.onerror = function(e) { reject(e.target.error); };
      });
    },

    deleteProject: async function(id) {
      await open();
      return new Promise(function(resolve, reject) {
        var t = tx(['projects', 'files'], 'readwrite');
        t.objectStore('projects').delete(id);
        var idx = t.objectStore('files').index('project');
        var cur = idx.openCursor(IDBKeyRange.only(id));
        cur.onsuccess = function(e) {
          var c = e.target.result;
          if (c) { c.delete(); c.continue(); }
        };
        t.oncomplete = function() { resolve(); };
        t.onerror = function(e) { reject(e.target.error); };
      });
    },

    saveFile: async function(projectId, path, content) {
      await open();
      var key = projectId + '::' + path;
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readwrite');
        t.objectStore('files').put({ key: key, project_id: projectId, path: path, content: content });
        t.oncomplete = function() { resolve(); };
        t.onerror = function(e) { reject(e.target.error); };
      });
    },

    getFile: async function(projectId, path) {
      await open();
      var key = projectId + '::' + path;
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readonly');
        var req = t.objectStore('files').get(key);
        req.onsuccess = function() { resolve(req.result ? req.result.content : null); };
        req.onerror = function(e) { reject(e.target.error); };
      });
    },

    listFiles: async function(projectId) {
      await open();
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readonly');
        var idx = t.objectStore('files').index('project');
        var req = idx.getAll(IDBKeyRange.only(projectId));
        req.onsuccess = function() {
          resolve((req.result || []).map(function(f) { return f.path; }));
        };
        req.onerror = function(e) { reject(e.target.error); };
      });
    },

    deleteFile: async function(projectId, path) {
      await open();
      var key = projectId + '::' + path;
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readwrite');
        t.objectStore('files').delete(key);
        t.oncomplete = function() { resolve(); };
        t.onerror = function(e) { reject(e.target.error); };
      });
    },

    getAllFiles: async function(projectId) {
      await open();
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readonly');
        var idx = t.objectStore('files').index('project');
        var req = idx.getAll(IDBKeyRange.only(projectId));
        req.onsuccess = function() {
          var map = {};
          (req.result || []).forEach(function(f) { map[f.path] = f.content; });
          resolve(map);
        };
        req.onerror = function(e) { reject(e.target.error); };
      });
    }
  };
})();

var _templateIndex = null;
async function loadTemplateIndex() {
  if (_templateIndex) return _templateIndex;
  try {
    var r = await fetch('templates/index.json');
    _templateIndex = await r.json();
  } catch (e) { _templateIndex = {}; }
  return _templateIndex;
}
async function fetchTemplateFiles(key) {
  var idx = await loadTemplateIndex();
  var tpl = idx[key];
  if (!tpl) return null;
  var files = {};
  for (var i = 0; i < tpl.files.length; i++) {
    var path = tpl.files[i];
    try {
      var r = await fetch('templates/' + key + '/' + path);
      files[path] = await r.text();
    } catch (e) { files[path] = ''; }
  }
  return { name: tpl.name, files: files };
}

var PROJECT_TEMPLATES = {
  empty: { name: 'Empty Project', files: { 'main.aml': 'contract MyContract {\n  state { owner: address }\n  constructor() {\n    self.owner = caller\n  }\n}' } },
  token: { name: 'OCS01 Token', files: { 'main.aml': '' } },
  vault: { name: 'Vault', files: { 'main.aml': '' } }
};

async function ideOpenProject(proj) {
  _ideProject = proj;
  _ideFiles = await ProjectStore.getAllFiles(proj.id);
  _ideOpenTabs = [];
  _ideActiveFile = null;
  _ideMode = true;

  var mainFile = 'main.aml';
  if (!_ideFiles[mainFile]) {
    var paths = Object.keys(_ideFiles);
    mainFile = paths.length > 0 ? paths[0] : null;
  }
  if (mainFile) {
    _ideOpenTabs = [mainFile];
    _ideActiveFile = mainFile;
  }

  ideRenderAll();
  updateVerifyUI();
}

function updateVerifyUI() {
  var single = $('ct-verify-single');
  var proj = $('ct-verify-project');
  var projFiles = $('ct-verify-project-files');
  if (!single || !proj) return;
  if (_ideProject && _ideFiles) {
    single.style.display = 'none';
    proj.style.display = '';
    var paths = Object.keys(_ideFiles);
    projFiles.innerHTML = paths.map(function(p) { return '<span class="ide-icon ide-file-icon"></span>' + escapeHtml(p); }).join('<br>');
  } else {
    single.style.display = '';
    proj.style.display = 'none';
  }
}

function ideRenderAll() {
  ideRenderProjectBar();
  ideRenderFileTree();
  ideRenderTabs();
  ideLoadActiveFile();
}

function ideRenderProjectBar() {
  var bar = $('ide-project-bar');
  if (!bar) return;
  if (!_ideProject) {
    bar.style.display = 'none';
    return;
  }
  bar.style.display = 'flex';
  bar.innerHTML = '<span class="ide-project-name">' + escapeHtml(_ideProject.name) + '</span>' +
    '<button class="ide-btn" onclick="ideCloseProject()" title="close project"><span class="ide-icon ico-close"></span></button>' +
    '<button class="ide-btn" onclick="ideExportZip()" title="export zip"><span class="ide-icon ico-download"></span></button>';
}

function ideRenderFileTree() {
  var tree = $('ide-file-tree');
  if (!tree) return;
  if (!_ideProject) {
    tree.style.display = 'none';
    return;
  }
  tree.style.display = 'block';
  var paths = Object.keys(_ideFiles).sort();
  var dirs = {};
  var rootFiles = [];
  paths.forEach(function(p) {
    var slash = p.indexOf('/');
    if (slash > 0) {
      var dir = p.substring(0, slash);
      if (!dirs[dir]) dirs[dir] = [];
      dirs[dir].push(p);
    } else {
      rootFiles.push(p);
    }
  });




  var html = '<div class="ide-tree-header">files <button class="ide-btn-small" onclick="ideNewFile()"><span class="ide-icon ico-plus"></span></button>' +
    '<label class="ide-btn-small" style="cursor:pointer" title="import .aml files"><span class="ide-icon ico-upload"></span><input type="file" accept=".aml,.json,.aml-project.json" multiple style="display:none" onchange="ideImportFiles(this.files)"></label>' +
    '<label class="ide-btn-small" style="cursor:pointer" title="import folder"><span class="ide-icon ico-folder-import"></span><input type="file" webkitdirectory style="display:none" onchange="ideImportFiles(this.files)"></label></div>';
  
  
  
  
    rootFiles.forEach(function(p) {
    var cls = p === _ideActiveFile ? ' active' : '';
    html += '<div class="ide-tree-file' + cls + '" onclick="ideOpenFile(\'' + escapeHtml(p) + '\')" oncontextmenu="ideFileMenu(event,\'' + escapeHtml(p) + '\')">' +
      '<span class="ide-icon ide-file-icon"></span>' + escapeHtml(p) + '</div>';
  });
  Object.keys(dirs).sort().forEach(function(dir) {
    html += '<div class="ide-tree-dir"><span class="ide-icon ide-dir-icon"></span>' + escapeHtml(dir) + '</div>';
    dirs[dir].sort().forEach(function(p) {
      var fname = p.substring(p.indexOf('/') + 1);
      var cls = p === _ideActiveFile ? ' active' : '';
      html += '<div class="ide-tree-file ide-tree-nested' + cls + '" onclick="ideOpenFile(\'' + escapeHtml(p) + '\')" oncontextmenu="ideFileMenu(event,\'' + escapeHtml(p) + '\')">' +
        '<span class="ide-icon ide-file-icon"></span>' + escapeHtml(fname) + '</div>';
    });
  });
  tree.innerHTML = html;
}

function ideRenderTabs() {
  var bar = $('ide-tabs');
  if (!bar) return;
  if (!_ideProject || _ideOpenTabs.length === 0) {
    bar.style.display = 'none';
    return;
  }
  bar.style.display = 'flex';
  var html = '';
  _ideOpenTabs.forEach(function(path) {
    var name = path.indexOf('/') >= 0 ? path.substring(path.lastIndexOf('/') + 1) : path;
    var cls = path === _ideActiveFile ? ' active' : '';
    html += '<div class="ide-tab' + cls + '" onclick="ideOpenFile(\'' + escapeHtml(path) + '\')">' +
      escapeHtml(name) +
      '<span class="ide-tab-close" onclick="event.stopPropagation();ideCloseTab(\'' + escapeHtml(path) + '\')">×</span>' +
      '</div>';
  });
  bar.innerHTML = html;
}

function ideLoadActiveFile() {
  var ta = $('ct-source');
  if (!ta) return;
  if (_ideActiveFile && _ideFiles[_ideActiveFile] !== undefined) {
    ta.value = _ideFiles[_ideActiveFile];
  } else {
    ta.value = '';
  }
  editorUpdate();
}

function ideOpenFile(path) {
  ideSaveCurrentFile();
  if (_ideOpenTabs.indexOf(path) < 0) {
    _ideOpenTabs.push(path);
  }
  _ideActiveFile = path;
  ideRenderFileTree();
  ideRenderTabs();
  ideLoadActiveFile();
}

function ideCloseTab(path) {
  ideSaveCurrentFile();
  var idx = _ideOpenTabs.indexOf(path);
  if (idx >= 0) _ideOpenTabs.splice(idx, 1);
  if (_ideActiveFile === path) {
    _ideActiveFile = _ideOpenTabs.length > 0 ? _ideOpenTabs[Math.max(0, idx - 1)] : null;
  }
  ideRenderTabs();
  ideRenderFileTree();
  ideLoadActiveFile();
}

function ideSaveCurrentFile() {
  if (!_ideProject || !_ideActiveFile) return;
  var ta = $('ct-source');
  if (!ta) return;
  _ideFiles[_ideActiveFile] = ta.value;
  ProjectStore.saveFile(_ideProject.id, _ideActiveFile, ta.value).catch(function() {});
}

async function ideNewFile() {
  var name = await idePrompt('new file', 'e.g. utils.aml or interfaces/IToken.aml');
  if (!name || !name.trim()) return;
  name = name.trim();
  if (_ideFiles[name] !== undefined) { alert('File already exists'); return; }
  _ideFiles[name] = '';
  await ProjectStore.saveFile(_ideProject.id, name, '');
  ideOpenFile(name);
}

async function ideFileMenu(e, path) {
  e.preventDefault();
  var action = await ideMenu(path, [
    {label: 'rename', value: 'rename'},
    {label: 'delete', value: 'delete'}
  ]);
  if (action === 'rename') {
    var newName = await idePrompt('rename file', '', path);
    if (newName && newName !== path) ideRenameFile(path, newName);
  } else if (action === 'delete') {
    var ok = await ideConfirm('delete file', 'delete ' + path + '?');
    if (ok) ideDeleteFile(path);
  }
}

async function ideRenameFile(oldPath, newPath) {
  if (_ideFiles[newPath] !== undefined) { alert('File already exists'); return; }
  _ideFiles[newPath] = _ideFiles[oldPath] || '';
  delete _ideFiles[oldPath];
  await ProjectStore.saveFile(_ideProject.id, newPath, _ideFiles[newPath]);
  await ProjectStore.deleteFile(_ideProject.id, oldPath);
  var idx = _ideOpenTabs.indexOf(oldPath);
  if (idx >= 0) _ideOpenTabs[idx] = newPath;
  if (_ideActiveFile === oldPath) _ideActiveFile = newPath;
  ideRenderAll();
}

async function ideDeleteFile(path) {
  delete _ideFiles[path];
  await ProjectStore.deleteFile(_ideProject.id, path);
  var idx = _ideOpenTabs.indexOf(path);
  if (idx >= 0) _ideOpenTabs.splice(idx, 1);
  if (_ideActiveFile === path) {
    _ideActiveFile = _ideOpenTabs.length > 0 ? _ideOpenTabs[0] : null;
  }
  ideRenderAll();
}

function ideCloseProject() {
  ideSaveCurrentFile();
  _ideProject = null;
  _ideFiles = {};
  _ideActiveFile = null;
  _ideOpenTabs = [];
  _ideMode = false;
  var tree = $('ide-file-tree');
  if (tree) tree.style.display = 'none';
  var bar = $('ide-project-bar');
  if (bar) bar.style.display = 'none';
  var tabs = $('ide-tabs');
  if (tabs) tabs.style.display = 'none';
  $('ct-source').value = '';
  editorUpdate();
  updateVerifyUI();
  showProjectPicker();
}

async function showProjectPicker() {
  var projects = await ProjectStore.listProjects();
  var pp = $('ide-project-picker');
  if (!pp) return;


  var html = '<div class="ide-picker-title">projects</div>';
  html += '<div class="ide-picker-section-label">new project</div>';
  html += '<div class="ide-picker-actions">';
  html += '<button class="action-btn" onclick="ideNewProject(\'empty\')"><span class="tpl-label">Blank</span><span class="tpl-desc">empty contract</span></button>';
  html += '<button class="action-btn" onclick="ideNewProject(\'token\')"><span class="tpl-label">OCS-01 Token</span><span class="tpl-desc">fungible token</span></button>';
  html += '<button class="action-btn" onclick="ideNewProject(\'vault\')"><span class="tpl-label">Vault</span><span class="tpl-desc">escrow contract</span></button>';
  html += '</div>';
  html += '<div class="ide-picker-import">';
  html += '<label class="action-btn" style="cursor:pointer"><span class="ide-icon ico-upload"></span> import files<input type="file" accept=".json,.aml-project.json,.aml" multiple style="display:none" onchange="ideImportFiles(this.files)"></label>';
  html += '<label class="action-btn" style="cursor:pointer"><span class="ide-icon ico-folder-import"></span> import folder<input type="file" webkitdirectory style="display:none" onchange="ideImportFiles(this.files)"></label>';
  html += '</div>';


  if (projects.length > 0) {
    html += '<div class="ide-picker-list">';
    html += '<div class="ide-picker-list-title">recent</div>';
    projects.forEach(function(p) {
      html += '<div class="ide-picker-item" onclick="ideLoadProject(\'' + p.id + '\')">' +
        '<span class="ide-picker-name">' + escapeHtml(p.name) + '</span>' +
        '<span class="ide-picker-date">' + new Date(p.created).toLocaleDateString() + '</span>' +
        '<button class="ide-btn-small" onclick="event.stopPropagation();ideDeleteProject(\'' + p.id + '\')" title="delete"><span class="ide-icon ico-delete"></span></button>' +
        '</div>';
    });
    html += '</div>';
  }
  pp.style.display = 'block';
  pp.innerHTML = html;
}

async function ideNewProject(template) {
  var tpl = await fetchTemplateFiles(template) || PROJECT_TEMPLATES[template] || PROJECT_TEMPLATES.empty;
  var name = await idePrompt('new project', '', tpl.name);
  if (!name || !name.trim()) return;
  var proj = await ProjectStore.createProject(name.trim(), template);
  var files = tpl.files;
  for (var path in files) {
    await ProjectStore.saveFile(proj.id, path, files[path]);
  }
  var pp = $('ide-project-picker');
  if (pp) pp.style.display = 'none';
  await ideOpenProject(proj);
}

async function ideLoadProject(id) {
  var projects = await ProjectStore.listProjects();
  var proj = projects.find(function(p) { return p.id === id; });
  if (!proj) return;
  var pp = $('ide-project-picker');
  if (pp) pp.style.display = 'none';
  await ideOpenProject(proj);
}

async function ideDeleteProject(id) {
  var ok = await ideConfirm('delete project', 'delete this project? this cannot be undone.');
  if (!ok) return;
  await ProjectStore.deleteProject(id);
  showProjectPicker();
}

async function ideExportZip() {
  if (!_ideProject) return;
  ideSaveCurrentFile();
  var bundle = {
    project: { name: _ideProject.name, template: _ideProject.template },
    files: _ideFiles
  };
  var blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (_ideProject.name || 'project').replace(/[^a-zA-Z0-9_-]/g, '_') + '.aml-project.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function ideImportFiles(fileList) {
  if (!fileList || fileList.length === 0) return;
  var files = Array.from(fileList);

  function getRelPath(f) {
    var rel = f.webkitRelativePath || '';
    if (rel) {
      var slash = rel.indexOf('/');
      if (slash >= 0) rel = rel.substring(slash + 1);
    }
    return rel || f.name;
  }

  var jsonFiles = files.filter(function(f) { return f.name.endsWith('.json'); });
  if (jsonFiles.length === 1 && files.length === 1) {
    var reader = new FileReader();
    reader.onload = async function(e) {
      try {
        var bundle = JSON.parse(e.target.result);
        if (!bundle.project || !bundle.files) { alert('Invalid project file'); return; }
        var proj = await ProjectStore.createProject(
          bundle.project.name || 'Imported',
          bundle.project.template || 'empty'
        );
        for (var path in bundle.files) {
          await ProjectStore.saveFile(proj.id, path, bundle.files[path]);
        }
        var pp = $('ide-project-picker');
        if (pp) pp.style.display = 'none';
        await ideOpenProject(proj);
      } catch (err) {
        alert('Import failed: ' + err.message);
      }
    };
    reader.readAsText(jsonFiles[0]);
    return;
  }

  var amlFiles = files.filter(function(f) { return f.name.endsWith('.aml'); });
  if (amlFiles.length === 0) { alert('Select .aml or .aml-project.json files'); return; }

  var folderName = '';
  if (amlFiles[0].webkitRelativePath) {
    folderName = amlFiles[0].webkitRelativePath.split('/')[0];
  }
  var projName = folderName || (amlFiles.length === 1 ? amlFiles[0].name.replace('.aml', '') : 'Imported');

  if (_ideProject) {
    for (var i = 0; i < amlFiles.length; i++) {
      var content = await amlFiles[i].text();
      var path = getRelPath(amlFiles[i]);
      _ideFiles[path] = content;
      await ProjectStore.saveFile(_ideProject.id, path, content);
    }
    ideRenderAll();
    return;
  }

  var proj = await ProjectStore.createProject(projName, 'empty');
  var hasMain = false;
  for (var i = 0; i < amlFiles.length; i++) {
    var content = await amlFiles[i].text();
    var path = getRelPath(amlFiles[i]);
    if (amlFiles.length === 1 && path !== 'main.aml') { path = 'main.aml'; }
    if (path === 'main.aml') hasMain = true;
    await ProjectStore.saveFile(proj.id, path, content);
  }
  if (!hasMain && amlFiles.length > 1) {
    await ProjectStore.saveFile(proj.id, 'main.aml', '');
  }
  var pp = $('ide-project-picker');
  if (pp) pp.style.display = 'none';
  await ideOpenProject(proj);
}

async function doCompileProject() {
  if (!_ideProject) { doCompile(); return; }
  ideSaveCurrentFile();
  clearResult('ct-compile-result');
  editorClearError();
  _compiledAbi = null;
  var abiDiv = $('ct-abi-display');
  if (abiDiv) abiDiv.style.display = 'none';

  var files = [];
  for (var path in _ideFiles) {
    files.push({ path: path, source: _ideFiles[path] });
  }
  if (files.length === 0) {
    showResult('ct-compile-result', false, 'no files in project');
    return;
  }
  try {
    var res = await api('POST', '/contract/compile-project', { files: files, main: 'main.aml' });
    var b64 = res.bytecode || '';
    $('ct-bytecode').value = b64;
    var ver = res.version ? ('AppliedML ' + res.version + ' - ') : '';
    var msg = ver + 'compiled: ' + res.instructions + ' instructions, ' + res.size + ' bytes (' + files.length + ' files)';
    showResult('ct-compile-result', true, msg);
    if (res.abi) {
      _compiledAbi = res.abi;
      if (abiDiv) {
        $('ct-abi-json').textContent = JSON.stringify(res.abi, null, 2);
        abiDiv.style.display = 'block';
      }
    }
    if (res.disasm) {
      var disEl = $('ct-disasm-code');
      if (disEl) disEl.innerHTML = highlightDisasm(res.disasm);
    }
    showBottomPanels();
    consoleLog('info', msg);
  } catch (e) {
    var errMsg = e.message || '';
    var lineMatch = errMsg.match(/line\s+(\d+)/i);
    if (lineMatch) editorMarkError(parseInt(lineMatch[1], 10));
    showResult('ct-compile-result', false, errMsg);
    consoleLog('error', 'compile error: ' + errMsg);
  }
}

async function doVerifyProject() {
  if (!_ideProject) { doVerifyContract(); return; }
  ideSaveCurrentFile();
  clearResult('ct-verify-result');
  var addr = $('ct-verify-addr').value.trim();
  if (!addr) { showResult('ct-verify-result', false, 'contract address required'); return; }

  var mainSource = _ideFiles['main.aml'] || '';
  if (!mainSource.trim()) { showResult('ct-verify-result', false, 'main.aml is empty'); return; }

  var depFiles = [];
  for (var path in _ideFiles) {
    if (path !== 'main.aml') {
      depFiles.push({ path: path, source: _ideFiles[path] });
    }
  }

  try {
    var payload = { address: addr, source: mainSource };
    if (depFiles.length > 0) payload.files = depFiles;
    var res = await api('POST', '/contract/verify', payload);
    showResult('ct-verify-result', true,
      'source verified - code_hash: <span class="mono">' + escapeHtml(res.code_hash || '') + '</span>');
  } catch (e) {
    showResult('ct-verify-result', false, e.message);
  }
}

function networkLabel(host) {
  if (host === '46.101.86.250') return 'main net';
  if (host === '165.227.225.79') return 'dev net';
  if (host === 'localhost' || host === '127.0.0.1') return 'local';
  return host;
}




function $(id) { return document.getElementById(id); }

function updateStealthBadge(count) {
  _unclaimedCount = count;
  var badge = $('stealth-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = 'inline-block';
  } else {
    badge.style.display = 'none';
  }
}

async function bgStealthScan() {
  try {
    var res = await api('GET', '/stealth/scan');
    var outputs = res.outputs || [];
    var unclaimed = 0;
    for (var i = 0; i < outputs.length; i++) {
      if (outputs[i].claimed) { delete _pendingClaimIds[String(outputs[i].id)]; continue; }
      if (!_pendingClaimIds[String(outputs[i].id)]) unclaimed++;
    }
    updateStealthBadge(unclaimed);
  } catch (e) {}
}

async function fetchBalance() {
  try {
    var bal = await api('GET', '/balance');
    _cachedBal = bal;
    var pub = bal.public_balance || '0';
    var enc = bal.encrypted_balance || '0';
    _encryptedBalanceRaw = parseInt(enc) || 0;
    var MAX_SANE_ENC = 100000000 * 1000000;
    var encCorrupt = (_encryptedBalanceRaw < 0 || _encryptedBalanceRaw > MAX_SANE_ENC);
    if (encCorrupt) _encryptedBalanceRaw = 0;
    if ($('btn-key-switch')) $('btn-key-switch').style.display = encCorrupt ? '' : 'none';
    if ($('st-balance')) $('st-balance').textContent = fmtOct(pub);
    if ($('st-enc-balance')) $('st-enc-balance').textContent = encCorrupt
        ? 'corrupted ciphertext' : fmtOct(enc);
    if ($('st-nonce')) $('st-nonce').textContent = bal.nonce || '0';
    if ($('st-staging')) $('st-staging').textContent = bal.staging || '0';
    if ($('send-bal')) $('send-bal').textContent = fmtOct(pub);
    if ($('enc-pub-bal')) $('enc-pub-bal').textContent = fmtOct(pub);
    if ($('enc-enc-bal')) $('enc-enc-bal').textContent = encCorrupt
        ? 'corrupted ciphertext' : fmtOct(enc);
    if ($('st-enc-bal-info')) $('st-enc-bal-info').textContent = encCorrupt
        ? 'corrupted ciphertext' : fmtOct(enc);
    if ($('ct-bal')) $('ct-bal').textContent = fmtOct(pub);
    $('hdr-status').textContent = _rpcHost ? 'online | ' + networkLabel(_rpcHost) : 'online';
    $('hdr-status').className = 'right online';
    return bal;
  } catch (e) {
    $('hdr-status').textContent = 'offline';
    $('hdr-status').className = 'right error';
    return null;
  }
}

async function api(method, path, body) {
  var controller = new AbortController();
  var timer = setTimeout(function() { controller.abort(); }, 60000);
  var opts = { method: method, headers: {}, signal: controller.signal };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  var res;
  try {
    res = await fetch('/api' + path, opts);
  } catch (e) {
    clearTimeout(timer);
    throw new Error(e.name === 'AbortError' ? 'empty response from RPC (possible timeout)' : e.message);
  }
  clearTimeout(timer);
  var text = await res.text();
  if (!text || text.length === 0) throw new Error('empty response from RPC (possible timeout)');
  var j;
  try { j = JSON.parse(text); } catch (e) { throw new Error('invalid server response: ' + text.substring(0, 200)); }
  if (!res.ok) throw new Error(j.error || j.message || 'request failed');
  return j;
}

async function fetchFees() {
  try {
    _fees = await api('GET', '/fee');
    applyFeeDefaults();
  } catch (e) {}
}

function ouToOct(ou) {
  var n = parseInt(ou);
  if (isNaN(n) || n <= 0) return '?';
  var oct = n / 1000000;
  return oct % 1 === 0 ? oct.toFixed(0) : oct.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
}

function applyFeeDefaults() {
  var map = {
    'send-fee': 'standard',
    'enc-fee': 'encrypt',
    'dec-fee': 'decrypt',
    'stealth-fee': 'stealth',
    'ct-deploy-fee': 'deploy',
    'ct-call-fee': 'call',
    'tok-fee': 'call'
  };
  for (var id in map) {
    var input = $(id);
    var fee = _fees[map[id]];
    if (input && fee) {
      var rec = fee.recommended || fee.minimum || '';
      if (!input.value || input.value === input.getAttribute('data-prev-default')) {
        input.value = rec;
        input.setAttribute('data-prev-default', rec);
      }
      input.placeholder = 'min: ' + (fee.minimum || '?');
    }
  }
  var btnDeploy = $('btn-deploy');
  if (btnDeploy && _fees.deploy) {
    var cost = _fees.deploy.base_fee || _fees.deploy.recommended;
    btnDeploy.textContent = 'deploy (' + ouToOct(cost) + ' oct)';
  }
}

function validateFee(inputId, opType) {
  var input = $(inputId);
  if (!input) return true;
  var val = input.value.trim();
  if (!val) return true;
  var n = parseInt(val);
  if (isNaN(n) || n <= 0 || String(n) !== val) return false;
  var fee = _fees[opType];
  if (fee && fee.minimum && n < parseInt(fee.minimum)) return false;
  return true;
}

function feeError(resultId, inputId, opType) {
  var fee = _fees[opType];
  var minStr = (fee && fee.minimum) ? fee.minimum : '?';
  showResult(resultId, false, 'invalid fee - must be integer >= ' + minStr);
  if ($(inputId)) $(inputId).focus();
}

function switchView(name) {
  if (name !== 'tx') _prevView = name;
  var views = document.querySelectorAll('.view');
  for (var i = 0; i < views.length; i++) views[i].classList.remove('active');
  var target = $('view-' + name);
  if (target) target.classList.add('active');
  var tabs = document.querySelectorAll('.nav-tabs a');
  for (var i = 0; i < tabs.length; i++) tabs[i].classList.remove('active');
  for (var i = 0; i < tabs.length; i++) {
    var t = tabs[i].textContent.trim();
var tabId = tabs[i].getAttribute('data-view');
    if (tabId === name) {
      tabs[i].classList.add('active');
      break;
    }
  }
  if (name === 'dashboard') loadDashboard();
  if (name === 'history') { _historyOffset = 0; loadHistory(); }
  if (name === 'keys') showKeys();
  if (name === 'settings') loadSettings();
  if (name === 'send') refreshSendBalance();
  if (name === 'dev' && !_ideProject) showProjectPicker();
  if (name === 'encrypt') refreshEncryptBalances();
  if (name === 'stealth') refreshStealthBalance();
  if (name === 'tokens') loadTokens();
  if (name === 'dev') refreshContractBalance();
  var devBtn = $('hdr-dev');
  if (devBtn) devBtn.style.background = (name === 'dev') ? '#3B567F' : '';
}

function goBack() {
  switchView(_prevView || 'dashboard');
}

function addCommas(s) {
  var parts = s.split('.');
  parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return parts.join('.');
}

function fmtOct(raw) {
  var v = parseFloat(raw);
  if (v === 0 || isNaN(v)) return '0 oct';
  var n = v / 1000000;
  var s = n.toFixed(6).replace(/\.?0+$/, '');
  return addCommas(s) + ' oct';
}

function formatUnits(rawStr, decimals) {
  var dec = parseInt(decimals) || 0;
  var s = String(rawStr).replace(/[^0-9]/g, '');
  if (s === '' || s === '0') return '0';
  if (dec === 0) return s;
  while (s.length <= dec) s = '0' + s;
  var intPart = s.slice(0, s.length - dec);
  var fracPart = s.slice(s.length - dec).replace(/0+$/, '');
  if (!intPart) intPart = '0';
  return fracPart ? intPart + '.' + fracPart : intPart;
}

function fmtTokenAmount(raw, decimals) {
  return addCommas(formatUnits(raw, decimals));
}

function fmtTokenCompact(raw, decimals) {
  var human = formatUnits(raw, decimals);
  if (human === '0') return '0';
  var n = parseFloat(human);
  if (n >= 1000000000) return (n / 1000000000).toFixed(1).replace(/\.0$/, '') + 'B';
  if (n >= 1000000) return (n / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
  return addCommas(human);
}

function fmtOctCompact(raw) {
  var v = parseFloat(raw);
  if (v === 0 || isNaN(v)) return '-';
  var n = v / 1000000;
  if (n >= 1000000) return (n / 1000000).toFixed(1).replace(/\.0$/, '') + 'M oct';
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'K oct';
  if (n > 0 && n < 0.001) return '< 0.001 oct';
  var s = n.toFixed(1);
  if (s === '0.0' && n > 0) s = n.toFixed(3).replace(/\.?0+$/, '');
  else s = s.replace(/\.0$/, '');
  return addCommas(s) + ' oct';
}

function fmtDate(ts) {
  if (ts == null || ts <= 0) return '';
  var d = new Date(ts * 1000);
  var pad = function(v) { return String(v).padStart(2, '0'); };
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}

function short(s) {
  if (!s || s.length <= 25) return s || '';
  return s.slice(0, 11) + '...' + s.slice(-11);
}

function txLinkExt(hash) {
  if (!hash) return '';
  if (!/^[a-f0-9]{64}$/.test(hash)) return '<span class="mono gray">' + escapeHtml(hash) + '</span>';
  var url = _explorerUrl + '/tx.html?hash=' + hash;
  return '<a class="mono" href="' + url + '" target="_blank" title="' + hash + '">' + short(hash) + '</a>';
}

function addrLink(addr) {
  if (!addr || addr === 'stealth' || addr === 'coinbase') return '<span class="gray">' + (addr || '-') + '</span>';
  if (!validAddr(addr)) return '<span class="mono gray">' + escapeHtml(addr) + '</span>';
  var display = short(addr);
  var url = _explorerUrl + '/address.html?addr=' + addr;
  return '<a class="mono addr" href="' + url + '" target="_blank" title="' + addr + '">' + display + '</a>';
}

function txLink(hash) {
  if (!hash) return '<span class="gray">-</span>';
  if (!/^[a-f0-9]{64}$/.test(hash)) return '<span class="mono gray">' + escapeHtml(hash) + '</span>';
  return '<a class="mono hash" href="javascript:void(0)" onclick="showTx(\'' + hash + '\')">' + short(hash) + '</a>';
}

function opTag(op) {
  if (op === 'stealth') return '<span class="stealth-tag">stealth</span>';
  if (op === 'claim') return '<span class="private-tag">claim</span>';
  if (op === 'encrypt') return '<span class="private-tag">encrypt</span>';
  if (op === 'decrypt') return '<span class="private-tag">decrypt</span>';
  if (op === 'private_transfer') return '<span class="private-tag">private</span>';
  if (op === 'deploy') return '<span class="contract-tag">contract_deploy</span>';
  if (op === 'call') return '<span class="contract-tag">contract_call</span>';
  if (op === 'key_switch') return '<span class="private-tag">key_switch</span>';
  return '';
}

function statusTag(st) {
  if (st === 'confirmed') return '<span class="private-tag">confirmed</span>';
  if (st === 'rejected') return '<span class="stealth-tag">rejected</span>';
  if (st === 'pending') return '<span class="pending-tag">pending</span>';
  return '<span class="pending-tag">' + escapeHtml(st || 'pending') + '</span>';
}

function showResult(elId, ok, msg) {
  var el = $(elId);
  if (!el) return;
  el.innerHTML = '<div class="result-msg ' + (ok ? 'result-ok' : 'result-error') + '">' + msg + '</div>';
}

function clearResult(elId) {
  var el = $(elId);
  if (el) el.innerHTML = '';
}

function validAddr(addr) {
  return /^oct[1-9A-HJ-NP-Za-km-z]{43,45}$/.test(addr);
}

function logStealth(msg, cls) {
  var el = $('stealth-log');
  if (!el) {
    var btn = document.querySelector('button[onclick="doStealthSend()"]');
    if (!btn) return;
    var row = btn.closest('.action-row') || btn.parentNode;
    el = document.createElement('div');
    el.id = 'stealth-log';
    row.parentNode.insertBefore(el, row.nextSibling);
  }
  el.innerHTML += '<div class="log-line' + (cls ? ' ' + cls : '') + '">' + msg + '</div>';
  el.scrollTop = el.scrollHeight;
}

function clearStealthLog() {
  var el = $('stealth-log');
  if (el) el.remove();
}

function logDecrypt(msg, cls) {
  var el = $('decrypt-log');
  if (!el) {
    var btn = document.querySelector('button[onclick="doDecrypt()"]');
    if (!btn) return;
    var row = btn.closest('.action-row') || btn.parentNode;
    el = document.createElement('div');
    el.id = 'decrypt-log';
    row.parentNode.insertBefore(el, row.nextSibling);
  }
  el.innerHTML += '<div class="log-line' + (cls ? ' ' + cls : '') + '">' + msg + '</div>';
  el.scrollTop = el.scrollHeight;
}

function clearDecryptLog() {
  var el = $('decrypt-log');
  if (el) el.remove();
}

function txStatusTag(st) {
  if (st === 'rejected') return '<span class="rejected-tag">rejected</span>';
  if (st === 'confirmed') return '<span class="confirmed-tag">confirmed</span>';
  if (st === 'pending') return '<span class="pending-tag">pending</span>';
  return '<span class="pending-tag">' + escapeHtml(st || 'pending') + '</span>';
}

function txAmt(tx) {
  var op = tx.op_type || '';
  if (op === 'call' && tx.encrypted_data === 'transfer' && tx.message) {
    var contract = tx.to_ || tx.to || '';
    var sym = _tokenSymbols[contract] || '';
    var dec = _tokenDecimals[contract] || '0';
    try {
      var p = JSON.parse(tx.message);
      if (Array.isArray(p) && p.length >= 2)
        return { amt: fmtTokenCompact(p[1], dec) + (sym ? ' ' + sym : ''), cls: '', toOverride: String(p[0]) };
    } catch(e) {}
  }
  var raw = tx.amount_raw ? parseFloat(tx.amount_raw) : 0;
  if (raw > 0) {
    var dir = '';
    if (tx.from === _walletAddr) dir = ' red';
    else if ((tx.to_ || tx.to) === _walletAddr) dir = ' green';
    return { amt: fmtOctCompact(tx.amount_raw), cls: dir, toOverride: null };
  }
  return { amt: '-', cls: ' gray', toOverride: null };
}

function txRow(tx) {
  var a = txAmt(tx);
  var toAddr = a.toOverride || (tx.to_ || tx.to);
  var st = tx.status || 'pending';
  var h = '<tr>';
  h += '<td>' + txLink(tx.hash) + '</td>';
  h += '<td>' + addrLink(tx.from) + '</td>';
  h += '<td>' + addrLink(toAddr) + '</td>';
  h += '<td class="mono amount' + a.cls + '">' + a.amt + '</td>';
  h += '<td>' + txStatusTag(st) + '</td>';
  h += '<td class="gray">' + fmtDate(tx.timestamp) + '</td>';
  h += '</tr>';
  return h;
}

function txCardHtml(tx) {
  var a = txAmt(tx);
  var toAddr = a.toOverride || (tx.to_ || tx.to);
  var st = tx.status || 'pending';
  var c = '<div class="tx-card">';
  c += '<div class="card-row"><span class="card-label">tx</span><span class="card-val">' + txLink(tx.hash) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">from</span><span class="card-val">' + addrLink(tx.from) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">to</span><span class="card-val">' + addrLink(toAddr) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">amount</span><span class="card-val mono amount' + a.cls + '">' + a.amt + '</span></div>';
  c += '<div class="card-row"><span class="card-label">status</span><span class="card-val">' + txStatusTag(st) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">time</span><span class="card-val gray">' + fmtDate(tx.timestamp) + '</span></div>';
  c += '</div>';
  return c;
}

async function showTx(hash) {
  switchView('tx');
  $('tx-detail').innerHTML = '<div class="loading">loading...</div>';
  try {
    var res = await api('GET', '/tx?hash=' + encodeURIComponent(hash));
    var st = res.status || 'pending';
    var h = '<table class="detail-table">';




    var fullHash = res.hash || hash;
    var explorerLink = _explorerUrl + '/tx.html?hash=' + fullHash;
    h += '<tr><td>hash</td><td class="mono">' + fullHash + ' <a href="' + explorerLink + '" target="_blank" style="font-size:10px;color:#8C9DB6;margin-left:4px">explorer</a></td></tr>';
    h += '<tr><td>status</td><td>' + txStatusTag(st) + '</td></tr>';
    if (res.reject_reason) h += '<tr><td>reason</td><td class="result-error">' + escapeHtml(res.reject_reason) + '</td></tr>';
      h += '<tr><td>from</td><td>' + addrLink(res.from || '') + '</td></tr>';
      h += '<tr><td>to</td><td>' + addrLink(res.to || res.to_ || '') + '</td></tr>';
       var amtRaw = res.amount_raw || res.amount || '0';
      h += '<tr><td>amount</td><td class="mono">' + fmtOct(amtRaw) + '</td></tr>';
      h += '<tr><td>amount (raw)</td><td class="mono gray">' + addCommas(String(amtRaw)) + '</td></tr>';
      var op = res.op_type || 'standard';
      h += '<tr><td>type</td><td>' + (opTag(op) || op) + '</td></tr>';
      if (res.epoch) h += '<tr><td>epoch</td><td>' + res.epoch + '</td></tr>';
      if (res.block_height) h += '<tr><td>block</td><td>' + res.block_height + '</td></tr>';
    h += '<tr><td>nonce</td><td>' + (res.nonce || '') + '</td></tr>';
    if (res.ou) h += '<tr><td>ou (fee)</td><td class="mono">' + fmtOct(res.ou) + '</td></tr>';
    h += '<tr><td>time</td><td>' + fmtDate(res.timestamp) + '</td></tr>';

    if (res.signature) h += '<tr><td>signature</td><td class="mono">' + res.signature + '</td></tr>';
    if (res.public_key) h += '<tr><td>public key</td><td class="mono">' + res.public_key + '</td></tr>';
    h += '</table>';
    if (res.message && res.message !== 'null' && res.message !== '') {
      h += '<div class="section-title">message</div>';
      h += '<div class="msg-box">' + escapeHtml(res.message) + '</div>';
    }
    $('tx-detail').innerHTML = h;
  } catch (e) {
    $('tx-detail').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

function escapeHtml(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function dashTxLimit() {
  var h = window.innerHeight;
  var overhead = 280;
  var rowH = 26;
  if (window.innerWidth < 700) { overhead = 300; rowH = 120; }
  return Math.max(5, Math.min(Math.floor((h - overhead) / rowH), 100));
}

function renderDashTxs(txs) {
  var h = '<table class="desktop-table"><tr><th>hash</th><th>from</th><th>to</th><th class="col-amount">amount</th><th class="col-status">status</th><th class="col-time">time</th></tr>';
  var cards = '<div class="card-list">';
  for (var i = 0; i < txs.length; i++) {
    h += txRow(txs[i]);
    cards += txCardHtml(txs[i]);
  }
  h += '</table>';
  cards += '</div>';
  $('dash-txs').innerHTML = h + cards;
  $('dash-more').innerHTML = '<div class="dash-more-row"><a href="#" onclick="switchView(\'history\');return false">view full history</a></div>';
}

async function loadDashboard() {
  await fetchBalance();
  loadTokenSymbols();
  try {
    var lim = dashTxLimit();
    var hist = await api('GET', '/history?limit=' + lim + '&offset=0');
    var txs = hist.transactions || [];
    if (txs.length === 0) {
      $('dash-txs').innerHTML = '<div class="staging-empty">no transactions yet</div>';
      $('dash-more').innerHTML = '';
      return;
    }
    renderDashTxs(txs);
    fetchMissingSymbols(txs).then(function() { renderDashTxs(txs); });
  } catch (e) {
    $('dash-txs').innerHTML = '<div class="staging-empty">no transactions yet</div>';
    $('dash-more').innerHTML = '';
  }
}

async function refreshSendBalance() {
  await fetchBalance();
}

async function doSend() {
  clearResult('send-result');
  var to = $('send-to').value.trim();
  var amount = $('send-amount').value.trim();
  var msg = $('send-msg') ? $('send-msg').value.trim() : '';
  if (!validAddr(to)) { showResult('send-result', false, 'invalid recipient address'); return; }
  if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) { showResult('send-result', false, 'invalid amount'); return; }
  if (!validateFee('send-fee', 'standard')) { feeError('send-result', 'send-fee', 'standard'); return; }
  try {
    var body = { to: to, amount: amount };
    if (msg) body.message = msg;
    var fee = $('send-fee') ? $('send-fee').value.trim() : '';
    if (fee) body.ou = fee;
    var res = await api('POST', '/send', body);
    var txHash = res.hash || res.tx_hash || '';
    showResult('send-result', true, 'sent ' + amount + ' oct - tx: ' + txLink(txHash));
    $('send-to').value = '';
    $('send-amount').value = '';
    if ($('send-msg')) $('send-msg').value = '';
    loadDashboard();
    refreshSendBalance();
  } catch (e) {
    showResult('send-result', false, e.message);
  }
}

async function refreshEncryptBalances() {
  await fetchBalance();
}

async function refreshStealthBalance() {
  await fetchBalance();
}

async function doKeySwitch() {
  hideAllModalPanels();
  $('modal-sub').textContent = 'encryption key switching';
  var h = '<div style="margin:20px 0;font-size:13px">';
  h += 'the ciphertext is corrupted or composed incorrectly (the consensus cannot process it), a key switch must be made</div>';
  h += '<div class="action-row">';
  h += '<button class="action-btn" id="ks-confirm">switch</button>';
  h += '<button class="action-btn" style="background:#8C9DB6" id="ks-cancel">cancel</button>';
  h += '</div>';
  $('modal-result').innerHTML = h;
  $('modal-overlay').style.display = 'flex';
  $('ks-cancel').onclick = function() {
    $('modal-result').innerHTML = '';
    $('modal-overlay').style.display = 'none';
  };
  $('ks-confirm').onclick = async function() {
    $('ks-confirm').disabled = true;
    $('ks-confirm').textContent = 'submitting...';
    try {
      var res = await api('POST', '/key_switch', {});
      var txHash = res.hash || res.tx_hash || '';
      var h2 = '<div class="result-msg result-ok" style="margin:20px 0;word-break:break-all">key switch submitted</div>';
      h2 += '<div style="margin:12px 0;font-size:13px">tx: ' + txLinkExt(txHash) + '</div>';
      h2 += '<div class="action-row"><button class="action-btn" id="ks-close">close</button></div>';
      $('modal-result').innerHTML = h2;
      $('ks-close').onclick = function() { $('modal-overlay').style.display = 'none'; fetchBalance(); };
    } catch (e) {
      $('modal-result').innerHTML = '<div class="result-msg result-error" style="margin:20px 0;word-break:break-all">' + e.message + '</div>';
    }
  };
}

async function doEncrypt() {
  clearResult('enc-result');
  var amount = $('enc-amount').value.trim();
  if (!amount || !/^\d+(\.\d{1,6})?$/.test(amount) || parseFloat(amount) <= 0) { showResult('enc-result', false, 'invalid amount'); return; }
  if (!validateFee('enc-fee', 'encrypt')) { feeError('enc-result', 'enc-fee', 'encrypt'); return; }
  try {
    var encBody = { amount: amount };
    var encFee = $('enc-fee') ? $('enc-fee').value.trim() : '';
    if (encFee) encBody.ou = encFee;
    var res = await api('POST', '/encrypt', encBody);
    var txHash = res.hash || res.tx_hash || '';
    showResult('enc-result', true, 'encrypted ' + amount + ' oct - tx: ' + txLink(txHash));
      $('enc-amount').value = '';
    loadDashboard();
    refreshEncryptBalances();
  } catch (e) {
    showResult('enc-result', false, e.message);
  }
}

async function doDecrypt() {
  clearResult('dec-result');
  clearDecryptLog();
  var amount = $('dec-amount').value.trim();
  if (!amount || !/^\d+(\.\d{1,6})?$/.test(amount) || parseFloat(amount) <= 0) { logDecrypt('error: invalid amount', 'log-err'); return; }
  var needRaw = Math.round(parseFloat(amount) * 1000000);
  if (_encryptedBalanceRaw <= 0) { logDecrypt('error: no encrypted balance to decrypt', 'log-err'); return; }
  if (needRaw > _encryptedBalanceRaw) { logDecrypt('error: insufficient encrypted balance: have ' + fmtOct(_encryptedBalanceRaw) + ', need ' + amount + ' oct', 'log-err'); return; }
  if (!validateFee('dec-fee', 'decrypt')) { logDecrypt('error: invalid fee - must be integer >= ' + ((_fees.decrypt && _fees.decrypt.minimum) || '?'), 'log-err'); return; }
  logDecrypt('initiating decrypt...', 'log-info');
  logDecrypt('amount: ' + amount + ' oct', 'log-info');
  logDecrypt('', '');
  try {
    var decBody = { amount: amount };
    var decFee = $('dec-fee') ? $('dec-fee').value.trim() : '';
    if (decFee) decBody.ou = decFee;
    var res = await api('POST', '/decrypt', decBody);
    if (res.steps) {
      for (var i = 0; i < res.steps.length; i++) logDecrypt(res.steps[i], 'log-info');
    }
    logDecrypt('', '');
    logDecrypt('decrypt complete', 'log-ok');
    if (res.hash || res.tx_hash) logDecrypt('tx: ' + txLink(res.hash || res.tx_hash), 'log-ok');
    $('dec-amount').value = '';
    loadDashboard();
    refreshEncryptBalances();
  } catch (e) {
    logDecrypt('error: ' + e.message, 'log-err');
  }
}






async function doStealthSend() {
  clearStealthLog();
  var to = $('stealth-to').value.trim();
  var amount = $('stealth-amount').value.trim();
  if (!validAddr(to)) { logStealth('error: invalid recipient address', 'log-err'); return; }
  if (!amount || !/^\d+(\.\d{1,6})?$/.test(amount) || parseFloat(amount) <= 0) { logStealth('error: invalid amount', 'log-err'); return; }
  var needRaw = Math.round(parseFloat(amount) * 1000000);
  if (_encryptedBalanceRaw <= 0) { logStealth('error: no encrypted balance - encrypt funds first', 'log-err'); return; }
  if (needRaw > _encryptedBalanceRaw) { logStealth('error: insufficient encrypted balance: have ' + fmtOct(_encryptedBalanceRaw) + ', need ' + amount + ' oct', 'log-err'); return; }
  if (!validateFee('stealth-fee', 'stealth')) { logStealth('error: invalid fee - must be integer >= ' + ((_fees.stealth && _fees.stealth.minimum) || '?'), 'log-err'); return; }
  logStealth('initiating stealth send...', 'log-info');




  
  logStealth('to: ' + to, 'log-info');
  logStealth('amount: ' + amount + ' oct', 'log-info');
  logStealth('', '');
  try {
    var stBody = { to: to, amount: amount };
    var stFee = $('stealth-fee') ? $('stealth-fee').value.trim() : '';
    if (stFee) stBody.ou = stFee;
    var res = await api('POST', '/stealth/send', stBody);
    if (res.steps) {
      for (var i = 0; i < res.steps.length; i++) logStealth(res.steps[i], 'log-info');
    }
    logStealth('', '');
    logStealth('stealth send complete', 'log-ok');
    if (res.tx_hash || res.hash) logStealth('tx: ' + (res.tx_hash || res.hash), 'log-ok');
    $('stealth-to').value = '';
    $('stealth-amount').value = '';
    loadDashboard();
    refreshStealthBalance();
  } catch (e) {
    logStealth('error: ' + e.message, 'log-err');
  }
}

async function doStealthScan() {
  $('stealth-outputs').innerHTML = '<div class="loading">scanning...</div>';
  try {
    var res = await api('GET', '/stealth/scan');
    var outputs = res.outputs || [];
    if (outputs.length === 0) {
      $('stealth-outputs').innerHTML = '<div class="staging-empty">no stealth outputs found</div>';
      return;
    }
    var h = '<table class="desktop-table stealth-table"><tr><th></th><th>id</th><th>amount</th><th>status</th></tr>';
    var cards = '<div class="card-list">';
    for (var i = 0; i < outputs.length; i++) {
      var o = outputs[i];
      var amt = o.amount_raw ? fmtOctCompact(o.amount_raw) : '?';
      var isPending = !o.claimed && _pendingClaimIds[String(o.id)];
      var st = o.claimed ? '<span class="gray">claimed</span>' : (isPending ? '<span class="gray">claiming\u2026</span>' : '<span class="green">unclaimed</span>');
      var chk = (o.claimed || isPending) ? '' : '<input type="checkbox" class="stealth-chk" data-id="' + o.id + '">';
      h += '<tr>';
      h += '<td>' + chk + '</td>';
      h += '<td class="mono">' + (o.id || '') + '</td>';
      h += '<td class="mono amount green">' + amt + '</td>';
      h += '<td>' + st + '</td>';
      h += '</tr>';
      cards += '<div class="tx-card">';

      if (!o.claimed) cards += '<div class="card-row"><span class="card-label">select</span><span class="card-val">' + chk + '</span></div>';
      cards += '<div class="card-row"><span class="card-label">id</span><span class="card-val mono">' + (o.id || '') + '</span></div>';
      cards += '<div class="card-row"><span class="card-label">amount</span><span class="card-val mono amount green">' + amt + '</span></div>';
      cards += '<div class="card-row"><span class="card-label">status</span><span class="card-val">' + st + '</span></div>';
      cards += '</div>';
    }




    h += '</table>';
    cards += '</div>';
    h += cards;
    var unclaimed = 0;
    for (var i = 0; i < outputs.length; i++) {
      if (outputs[i].claimed) { delete _pendingClaimIds[String(outputs[i].id)]; continue; }
      if (!_pendingClaimIds[String(outputs[i].id)]) unclaimed++;
    }
    updateStealthBadge(unclaimed);
    if (unclaimed > 0) {
      h += '<div class="claim-row"><button class="action-btn" onclick="claimSelected()">claim selected</button></div>';
    }
    $('stealth-outputs').innerHTML = h;
  } catch (e) {
    $('stealth-outputs').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

function claimSelected() {
  var checks = document.querySelectorAll('.stealth-chk:checked');
  var ids = [];
  for (var i = 0; i < checks.length; i++) ids.push(checks[i].getAttribute('data-id'));
  if (ids.length === 0) return;
  doStealthClaim(ids);
}

async function doStealthClaim(ids) {
  clearStealthLog();
  logStealth('claiming ' + ids.length + ' output(s)...', 'log-info');
  try {
    var res = await api('POST', '/stealth/claim', { ids: ids });
    logStealth('claim complete', 'log-ok');
    if (res.results) {
      for (var i = 0; i < res.results.length; i++) {
        var r = res.results[i];
        logStealth(r.id + ': ' + (r.ok ? 'ok' : 'failed - ' + (r.error || '')), r.ok ? 'log-ok' : 'log-err');
        if (r.ok) _pendingClaimIds[String(r.id)] = true;
      }
    }
    doStealthScan();
    loadDashboard();
    pollPendingClaims();
  } catch (e) {
    logStealth('error: ' + e.message, 'log-err');
  }
}

function pollPendingClaims() {
  if (Object.keys(_pendingClaimIds).length === 0) return;
  var attempts = 0;
  var poll = setInterval(async function() {
    attempts++;
    if (attempts > 6 || Object.keys(_pendingClaimIds).length === 0) { clearInterval(poll); return; }
    await doStealthScan();
    await loadDashboard();
  }, 12000);
}

async function refreshContractBalance() {
  await fetchBalance();
}

var _editorErrorLine = -1;

function escapeHtmlCode(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

var _amlRe = /(\/\*[\s\S]*?\*\/)|(\/\/[^\n]*)|("(?:[^"\\]|\\.)*")|(\b(?:contract|state|constructor|fn|view|let|if|else|while|for|in|return|assert|require|match|const|struct|enum|true|false|payable|nonreentrant|public|private|internal|event|error|import|interface|implements|indexed)\b)|(\b(?:string|int|bool|address|bytes|cipher|pubkey|map|list|void)\b)|(\b(?:self_addr|transfer|call|to_int|checkpoint|rollback|commit|origin|caller|balance|emit|log|value|epoch|min|max|abs|concat|to_string|len|split|join|replace|pow|sha256|keccak256|is_address|assert_address|starts_with|substr|index_of|bit_and|bit_or|bit_xor|parse_ints|mget|mset|blob_store|blob_load|some|none|is_some_opt|unwrap|fhe_load_pk|fhe_add|fhe_sub|fhe_scale|fhe_add_const|fhe_sub_const|fhe_verify_zero|fhe_verify_range|fhe_verify_bound|fhe_commit|fhe_pedersen|fhe_ser|fhe_deser)\b)|(\bself\b)|(\b[0-9]+\b)|([+\-*\/]=|[=!<>]=|&&|\|\||->|\?|[+\-*\/%<>=!])/g;

function highlightAml(src) {
  _amlRe.lastIndex = 0;
  var out = '';
  var last = 0;
  var m;
  while ((m = _amlRe.exec(src)) !== null) {
    if (m.index > last) out += escapeHtmlCode(src.slice(last, m.index));
    var tok = escapeHtmlCode(m[0]);
    if (m[1]) out += '<span class="aml-comment">' + tok + '</span>';
    else if (m[2]) out += '<span class="aml-comment">' + tok + '</span>';
    else if (m[3]) out += '<span class="aml-str">' + tok + '</span>';
    else if (m[4]) out += '<span class="aml-kw">' + tok + '</span>';
    else if (m[5]) out += '<span class="aml-type">' + tok + '</span>';
    else if (m[6]) out += '<span class="aml-builtin">' + tok + '</span>';
    else if (m[7]) out += '<span class="aml-self">' + tok + '</span>';
    else if (m[8]) out += '<span class="aml-num">' + tok + '</span>';
    else if (m[9]) out += '<span class="aml-op">' + tok + '</span>';
    last = m.index + m[0].length;
  }
  if (last < src.length) out += escapeHtmlCode(src.slice(last));
  return out + '\n';
}

var _asmRe = /(;[^\n]*)|("(?:[^"\\]|\\.)*")|(\br[0-9]{1,2}\b)|(\b[A-Z_]{2,}\b)|(\b[0-9]+\b)/g;

function highlightAsm(src) {
  _asmRe.lastIndex = 0;
  var out = '';
  var last = 0;
  var m;
  while ((m = _asmRe.exec(src)) !== null) {
    if (m.index > last) out += escapeHtmlCode(src.slice(last, m.index));
    var tok = escapeHtmlCode(m[0]);
    if (m[1]) out += '<span class="asm-comment">' + tok + '</span>';
    else if (m[2]) out += '<span class="asm-str">' + tok + '</span>';
    else if (m[3]) out += '<span class="asm-reg">' + tok + '</span>';
    else if (m[4]) out += '<span class="asm-instr">' + tok + '</span>';
    else if (m[5]) out += '<span class="asm-num">' + tok + '</span>';
    last = m.index + m[0].length;
  }
  if (last < src.length) out += escapeHtmlCode(src.slice(last));
  return out + '\n';
}

function updateGutter(src) {
  var g = $('ct-gutter');
  if (!g) return;
  var n = (src.match(/\n/g) || []).length + 1;
  var lines = [];
  for (var i = 1; i <= n; i++) {
    if (i === _editorErrorLine) lines.push('<span class="gutter-error">' + i + '</span>');
    else lines.push('' + i);
  }
  g.innerHTML = lines.join('\n');
}

function editorUpdate() {
  var ta = $('ct-source');
  var hl = $('ct-highlight');
  if (!ta || !hl) return;
  var src = ta.value;
  var lang = $('ct-lang').value;
  hl.innerHTML = lang === 'aml' ? highlightAml(src) : highlightAsm(src);
  updateGutter(src);
  editorSync();
  if (_ideProject && _ideActiveFile) {
    _ideFiles[_ideActiveFile] = src;
    if (_ideSaveTimer) clearTimeout(_ideSaveTimer);
    _ideSaveTimer = setTimeout(function() {
      ProjectStore.saveFile(_ideProject.id, _ideActiveFile, src).catch(function() {});
    }, 2000);
  }
}

function editorSync() {
  var ta = $('ct-source');
  var hl = $('ct-highlight');
  var g = $('ct-gutter');
  if (!ta || !hl) return;
  hl.style.transform = 'translate(' + (-ta.scrollLeft) + 'px,' + (-ta.scrollTop) + 'px)';
  if (g) g.scrollTop = ta.scrollTop;
}

function editorMarkError(lineNum) {
  _editorErrorLine = lineNum;
  var ta = $('ct-source');
  if (ta) updateGutter(ta.value);
}

function editorClearError() {
  _editorErrorLine = -1;
  var ta = $('ct-source');
  if (ta) updateGutter(ta.value);
}

function initEditor() {
  var ta = $('ct-source');
  if (!ta) return;
  ta.addEventListener('keydown', function(e) {
    if (e.key === 'Tab') {
      e.preventDefault();
      var start = ta.selectionStart;
      var end = ta.selectionEnd;
      var val = ta.value;
      ta.value = val.substring(0, start) + '  ' + val.substring(end);
      ta.selectionStart = ta.selectionEnd = start + 2;
      editorUpdate();
    }
  });
  editorUpdate();
}

function onLangChange() {
  var lang = $('ct-lang').value;
  var ta = $('ct-source');
  if (lang === 'aml') {
    $('ct-source-label').textContent = 'AppliedML source (.aml)';
    ta.placeholder = 'contract Token {\n  state { name: string }\n  constructor(n: string) {\n    self.name = n\n  }\n}';
  } else {
    $('ct-source-label').textContent = 'assembly source (.oasm)';
    ta.placeholder = '; constructor\nCALLER r0\nSSTORE "owner", r0\nSTOP\n; dispatcher\nJDEST 100\n...';
  }
  ta.value = '';
  editorUpdate();
}

async function doCompile() {
  if (_ideProject) { doCompileProject(); return; }
  clearResult('ct-compile-result');
  editorClearError();
  _compiledAbi = null;
  var source = $('ct-source').value;
  var lang = $('ct-lang').value;
  if (!source.trim()) { showResult('ct-compile-result', false, 'source required'); return; }
  try {
    var endpoint = lang === 'aml' ? '/contract/compile-aml' : '/contract/compile';
    var res = await api('POST', endpoint, { source: source });
    var b64 = res.bytecode || '';
    $('ct-bytecode').value = b64;
    var ver = res.version ? ('AppliedML ' + res.version + ' - ') : '';
    var msg = ver + 'compiled: ' + res.instructions + ' instructions, ' + res.size + ' bytes';
    showResult('ct-compile-result', true, msg);
    if (res.abi) {
      _compiledAbi = res.abi;
      var abiEl = $('ct-abi-json');
      if (abiEl) abiEl.textContent = JSON.stringify(res.abi, null, 2);
    }
    if (res.disasm) {
      var disEl = $('ct-disasm-code');
      if (disEl) disEl.innerHTML = highlightDisasm(res.disasm);
    }
    showBottomPanels();
    consoleLog('info', msg);
  } catch (e) {
    var errMsg = e.message || '';
    var lineMatch = errMsg.match(/line\s+(\d+)/i);
    if (lineMatch) editorMarkError(parseInt(lineMatch[1], 10));
    showResult('ct-compile-result', false, errMsg);
    consoleLog('error', 'compile error: ' + errMsg);
  }
}

function switchBottomTab(panel) {
  var tabs = document.querySelectorAll('.ide-bottom-tab');
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].classList.toggle('active', tabs[i].getAttribute('data-panel') === panel);
  }
  var panels = document.querySelectorAll('.ide-bottom-panel');
  for (var i = 0; i < panels.length; i++) {
    var id = panels[i].id.replace('ct-','').replace('-display','');
    panels[i].style.display = id === panel ? 'block' : 'none';
    panels[i].classList.toggle('active', id === panel);
  }
}

function showBottomPanels() {
  var panels = document.querySelectorAll('.ide-bottom-panel');
  var activePanel = null;
  var tabs = document.querySelectorAll('.ide-bottom-tab');
  for (var i = 0; i < tabs.length; i++) {
    if (tabs[i].classList.contains('active')) { activePanel = tabs[i].getAttribute('data-panel'); break; }
  }
  if (!activePanel) activePanel = 'abi';
  switchBottomTab(activePanel);
}

var _consoleLogs = [];
function consoleLog(level, msg) {
  var ts = new Date().toLocaleTimeString();
  _consoleLogs.push({ level: level, msg: msg, ts: ts });
  if (_consoleLogs.length > 200) _consoleLogs.shift();
  renderConsole();
}

function consoleClear() {
  _consoleLogs = [];
  renderConsole();
}

function renderConsole() {
  var el = $('ct-console-output');
  if (!el) return;
  var html = '';
  for (var i = 0; i < _consoleLogs.length; i++) {
    var l = _consoleLogs[i];
    html += '<div class="console-line ' + l.level + '">' +
      '<span class="timestamp">' + escapeHtml(l.ts) + '</span>' +
      '<span class="label">[' + l.level.toUpperCase() + ']</span> ' +
      escapeHtml(l.msg) + '</div>';
  }
  el.innerHTML = html || '<div class="console-line info" style="color:#666">no output yet</div>';
  el.scrollTop = el.scrollHeight;
}

function highlightDisasm(src) {
  var lines = src.split('\n');
  var html = '';
  for (var i = 0; i < lines.length; i++) {
    var line = escapeHtml(lines[i]);
    line = line.replace(/(;.*)$/, '<span class="cmt">$1</span>');
    line = line.replace(/("(?:[^"\\]|\\.)*")/g, '<span class="str">$1</span>');
    line = line.replace(/\b(r[0-9]{1,2})\b/g, '<span class="reg">$1</span>');
    line = line.replace(/\b(\-?[0-9]+)\b/g, '<span class="num">$1</span>');
    line = line.replace(/^(\s*)(JDEST)/, '$1<span class="lbl">$2</span>');
    line = line.replace(/^(\s*)([A-Z_]{2,})/, '$1<span class="op">$2</span>');
    html += line + '\n';
  }
  return html;
}

async function loadTemplate() {
  var sel = $('ct-template');
  if (!sel) return;
  var key = sel.value;
  if (!key) return;
  try {
    var r = await fetch('templates/' + key + '/main.aml');
    if (!r.ok) return;
    var source = await r.text();
    var ta = $('ct-source');
    if (ta) { ta.value = source; editorUpdate(); }
  } catch (e) {}
  sel.value = '';
}

document.addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    var devView = $('view-dev');
    if (devView && devView.classList.contains('active')) {
      e.preventDefault();
      doCompile();
    }
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    var devView = $('view-dev');
    if (devView && devView.classList.contains('active')) {
      e.preventDefault();
      doDeploy();
    }
  }
});

var _liveCompileTimer = null;
var _liveCompileEnabled = true;
function editorUpdateWithLiveCompile() {
  editorUpdate();
  if (!_liveCompileEnabled) return;
  if (_liveCompileTimer) clearTimeout(_liveCompileTimer);
  _liveCompileTimer = setTimeout(function() {
    var source = $('ct-source').value;
    if (source.trim().length > 10) doCompile();
  }, 1500);
}

function updateStorageView(storage) {
  var el = $('ct-storage-output');
  if (!el || !storage) return;
  var keys = Object.keys(storage).sort();
  if (keys.length === 0) {
    el.innerHTML = '<div style="color:#666">no storage entries</div>';
    return;
  }
  var html = '';
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = storage[k];
    if (typeof v === 'string' && v.length > 80) v = v.slice(0, 80) + '...';
    html += '<div class="storage-row"><span class="storage-key">' +
      escapeHtml(k) + '</span><span class="storage-val">' +
      escapeHtml(String(v)) + '</span></div>';
  }
  el.innerHTML = html;
}

async function doPreviewDeploy() {
  clearResult('ct-deploy-result');
  var bytecode = $('ct-bytecode').value.trim();
  if (!bytecode) { showResult('ct-deploy-result', false, 'bytecode required (compile first)'); return; }
  try {
    var res = await api('POST', '/contract/address', { bytecode: bytecode });
    showResult('ct-deploy-result', true,
      'predicted address: <span class="mono">' + escapeHtml(res.address) + '</span> (nonce ' + res.nonce + ')');
  } catch (e) {
    showResult('ct-deploy-result', false, e.message);
  }
}

function verifySourceRetry(addr, source, depFiles, attempts) {
  if (attempts <= 0) return;
  setTimeout(async function() {
    try {
      var payload = { address: addr, source: source };
      if (depFiles && depFiles.length > 0) payload.files = depFiles;
      await api('POST', '/contract/verify', payload);
      showResult('ct-deploy-result', true,
        'deployed to <span class="mono">' + escapeHtml(addr) + '</span> - <strong>source verified</strong>');
    } catch (e) {
      verifySourceRetry(addr, source, depFiles, attempts - 1);
    }
  }, 12000);
}

async function doDeploy() {
  clearResult('ct-deploy-result');
  var bytecode = $('ct-bytecode').value.trim();
  if (!bytecode) { showResult('ct-deploy-result', false, 'bytecode required (compile first)'); return; }
  var params = $('ct-deploy-params').value.trim();
  if (params && params !== '[]') {
    try { JSON.parse(params); } catch (e) {
      showResult('ct-deploy-result', false, 'invalid json params');
      return;
    }
  }
  if (!validateFee('ct-deploy-fee', 'deploy')) { feeError('ct-deploy-result', 'ct-deploy-fee', 'deploy'); return; }
  try {
    var body = { bytecode: bytecode };
    if (params) body.params = params;
    var deployFee = $('ct-deploy-fee') ? $('ct-deploy-fee').value.trim() : '';
    if (deployFee) body.ou = deployFee;
    var res = await api('POST', '/contract/deploy', body);
    var addr = res.contract_address || '';
    var hash = res.tx_hash || '';
    showResult('ct-deploy-result', true,
      'deployed to <span class="mono">' + escapeHtml(addr) + '</span> - tx: ' + txLink(hash) + ' (verifying source...)');
    $('ct-call-addr').value = addr;
    $('ct-info-addr').value = addr;
    var source = _ideProject ? (_ideFiles['main.aml'] || '') : ($('ct-source').value || '');
    var depFiles = [];
    if (_ideProject) {
      for (var path in _ideFiles) {
        if (path !== 'main.aml') depFiles.push({ path: path, source: _ideFiles[path] });
      }
    }
    if (source.trim()) verifySourceRetry(addr, source, depFiles, 5);
    loadDashboard();
  } catch (e) {
    showResult('ct-deploy-result', false, e.message);
  }
}

async function doContractCall() {
  clearResult('ct-call-result');
  var addr = $('ct-call-addr').value.trim();
  var method = $('ct-call-method').value.trim();
  if (!addr) { showResult('ct-call-result', false, 'contract address required'); return; }
  if (!method) { showResult('ct-call-result', false, 'method name required'); return; }
  var params_str = $('ct-call-params').value.trim() || '[]';
  var params;
  try { params = JSON.parse(params_str); } catch (e) {
    showResult('ct-call-result', false, 'invalid json params');
    return;
  }
  var amount = $('ct-call-amount').value.trim() || '0';
  var amount_raw = '0';
  if (amount !== '0' && amount !== '') {
    var f = parseFloat(amount);
    if (isNaN(f) || f < 0) { showResult('ct-call-result', false, 'invalid amount'); return; }
    amount_raw = String(Math.round(f * 1000000));
  }
  if (!validateFee('ct-call-fee', 'call')) { feeError('ct-call-result', 'ct-call-fee', 'call'); return; }
  try {
    var callBody = { address: addr, method: method, params: params, amount: amount_raw };
    var callFee = $('ct-call-fee') ? $('ct-call-fee').value.trim() : '';
    if (callFee) callBody.ou = callFee;
    var res = await api('POST', '/contract/call', callBody);
    var hash = res.tx_hash || '';
    showResult('ct-call-result', true, 'call submitted - tx: ' + txLink(hash));
    consoleLog('event', 'call ' + method + '() → tx ' + (hash ? hash.slice(0,16) + '...' : ''));
    loadDashboard();
  } catch (e) {
    showResult('ct-call-result', false, e.message);
    consoleLog('error', 'call ' + method + '() failed: ' + e.message);
  }
}

async function expandEncParams(params_str) {
  var re = /enc\((-?\d+)\)/g;
  var match;
  var replacements = [];
  while ((match = re.exec(params_str)) !== null) {
    replacements.push({start: match.index, end: match.index + match[0].length, value: parseInt(match[1])});
  }
  if (replacements.length === 0) return params_str;
  for (var i = replacements.length - 1; i >= 0; i--) {
    var r = replacements[i];
    var res = await api('POST', '/fhe/encrypt', {value: r.value});
    params_str = params_str.substring(0, r.start) + '"' + res.ciphertext + '"' + params_str.substring(r.end);
  }
  return params_str;
}

async function tryFheDecrypt(val) {
  if (typeof val !== 'string' || val.length < 100) return null;
  try {
    var res = await api('POST', '/fhe/decrypt', {ciphertext: val});
    return res.value;
  } catch (e) {
    return null;
  }
}

async function doContractView() {
  clearResult('ct-call-result');
  var addr = $('ct-call-addr').value.trim();
  var method = $('ct-call-method').value.trim();
  if (!addr) { showResult('ct-call-result', false, 'contract address required'); return; }
  if (!method) { showResult('ct-call-result', false, 'method name required'); return; }
  var params_str = $('ct-call-params').value.trim() || '[]';
  try {
    showResult('ct-call-result', true, '<span class="mono">processing...</span>');
    params_str = await expandEncParams(params_str);
    try { JSON.parse(params_str); } catch (e) {
      showResult('ct-call-result', false, 'invalid json params');
      return;
    }
    var url = '/contract/view?address=' + encodeURIComponent(addr) +
      '&method=' + encodeURIComponent(method) +
      '&params=' + encodeURIComponent(params_str);
    var res = await api('GET', url);
    var val = res.result;
    if (val === null || val === undefined) val = 'null';
    var decrypted = await tryFheDecrypt(val);
    if (decrypted !== null) {
      showResult('ct-call-result', true,
        'result (encrypted): <span class="mono">' + escapeHtml(String(val)).substring(0, 40) + '...</span>' +
        '<br>decrypted: <span class="mono" style="color:#0f0;font-size:1.1em">' + decrypted + '</span>');
      consoleLog('log', 'view ' + method + '() → ' + decrypted + ' (decrypted)');
    } else {
      showResult('ct-call-result', true, 'result: <span class="mono">' + escapeHtml(String(val)) + '</span>');
      consoleLog('log', 'view ' + method + '() → ' + String(val));
    }
    if (res.storage) updateStorageView(res.storage);
    if (res.events && res.events.length > 0) {
      for (var i = 0; i < res.events.length; i++) {
        consoleLog('event', 'emit ' + res.events[i].name + '(' + (res.events[i].args || []).join(', ') + ')');
      }
    }
  } catch (e) {
    showResult('ct-call-result', false, e.message);
    consoleLog('error', 'view ' + method + '() failed: ' + e.message);
  }
}

async function doFheEncrypt() {
  clearResult('fhe-result');
  var val = $('fhe-enc-value').value.trim();
  if (val === '') { showResult('fhe-result', false, 'enter an integer value'); return; }
  var num = parseInt(val);
  if (isNaN(num)) { showResult('fhe-result', false, 'invalid integer'); return; }
  try {
    var res = await api('POST', '/fhe/encrypt', {value: num});
    $('fhe-enc-output').value = res.ciphertext;
    $('fhe-enc-result-row').style.display = '';
    showResult('fhe-result', true, 'encrypted ' + num + ' (' + res.ciphertext.length + ' chars)');
  } catch (e) {
    showResult('fhe-result', false, e.message);
  }
}

async function doFheDecrypt() {
  clearResult('fhe-result');
  var ct = $('fhe-dec-input').value.trim();
  if (!ct) { showResult('fhe-result', false, 'paste a ciphertext'); return; }
  try {
    var res = await api('POST', '/fhe/decrypt', {ciphertext: ct});
    showResult('fhe-result', true, 'decrypted value: <span class="mono">' + res.value + '</span>');
  } catch (e) {
    showResult('fhe-result', false, e.message);
  }
}

async function doContractInfo() {
  clearResult('ct-info-result');
  var addr = $('ct-info-addr').value.trim();
  if (!addr) { showResult('ct-info-result', false, 'address required'); return; }
  try {
    var res = await api('GET', '/contract/info?address=' + encodeURIComponent(addr));
    var h = '<table class="detail-table">';
    h += '<tr><td>address</td><td class="mono">' + escapeHtml(res.address || addr) + '</td></tr>';
    h += '<tr><td>owner</td><td class="mono">' + escapeHtml(res.owner || '') + '</td></tr>';
    h += '<tr><td>version</td><td>' + escapeHtml(res.version || '') + '</td></tr>';
    h += '<tr><td>code hash</td><td class="mono">' + escapeHtml(res.code_hash || '') + '</td></tr>';
    h += '<tr><td>balance</td><td class="mono">' + fmtOct(res.balance || '0') + '</td></tr>';
    h += '</table>';
    $('ct-info-result').innerHTML = h;
  } catch (e) {
    showResult('ct-info-result', false, e.message);
  }
}

async function doContractReceipt() {
  clearResult('ct-info-result');
  var addr = $('ct-info-addr').value.trim();
  if (!addr) { showResult('ct-info-result', false, 'enter a tx hash to lookup receipt'); return; }
  try {
    var res = await api('GET', '/contract/receipt?hash=' + encodeURIComponent(addr));
    var h = '<table class="detail-table">';
    var keys = Object.keys(res);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var v = res[k];
      if (typeof v === 'object') v = JSON.stringify(v);
      h += '<tr><td>' + escapeHtml(k) + '</td><td class="mono">' + escapeHtml(String(v)) + '</td></tr>';
    }
    h += '</table>';
    $('ct-info-result').innerHTML = h;
  } catch (e) {
    showResult('ct-info-result', false, e.message);
  }
}

async function doVerifyContract() {
  if (_ideProject) { doVerifyProject(); return; }
  clearResult('ct-verify-result');
  var addr = $('ct-verify-addr').value.trim();
  var source = $('ct-verify-source').value;
  if (!addr) { showResult('ct-verify-result', false, 'contract address required'); return; }
  if (!source.trim()) { showResult('ct-verify-result', false, 'source required'); return; }
  try {
    var res = await api('POST', '/contract/verify', { address: addr, source: source });
    showResult('ct-verify-result', true,
      'source verified - code_hash: <span class="mono">' + escapeHtml(res.code_hash || '') + '</span>');
  } catch (e) {
    showResult('ct-verify-result', false, e.message);
  }
}

async function loadTokenSymbols() {
  if (_tokensLoaded) return;
  try {
    var res = await api('GET', '/tokens');
    _tokens = res.tokens || [];
    _tokensLoaded = true;
    for (var i = 0; i < _tokens.length; i++) {
      _tokenSymbols[_tokens[i].address] = _tokens[i].symbol;
      _tokenDecimals[_tokens[i].address] = _tokens[i].decimals || '0';
    }
  } catch(e) {}
}

async function fetchMissingSymbols(txs) {
  var need = {};
  for (var i = 0; i < txs.length; i++) {
    var t = txs[i];
    if (t.op_type === 'call' && t.encrypted_data === 'transfer') {
      var ca = t.to_ || t.to || '';
      if (ca && !_tokenSymbols[ca]) need[ca] = true;
    }
  }
  var unknowns = Object.keys(need);
  if (unknowns.length === 0) return;
  await Promise.all(unknowns.map(function(ca) {
    return Promise.all([
      api('GET', '/contract-storage?address=' + encodeURIComponent(ca) + '&key=symbol').then(function(r) {
        if (r && r.value) _tokenSymbols[ca] = String(r.value).slice(0, 32);
      }).catch(function() {}),
      api('GET', '/contract-storage?address=' + encodeURIComponent(ca) + '&key=decimals').then(function(r) {
        if (r && r.value) _tokenDecimals[ca] = String(r.value);
      }).catch(function() {})
    ]);
  }));
}

async function loadTokens() {
  $('tok-list').innerHTML = '<div class="loading">loading tokens...</div>';
  try {
    var res = await api('GET', '/tokens');
    _tokens = res.tokens || [];
    _tokensLoaded = true;
    for (var i = 0; i < _tokens.length; i++) {
      _tokenSymbols[_tokens[i].address] = _tokens[i].symbol;
      _tokenDecimals[_tokens[i].address] = _tokens[i].decimals || '0';
    }
    renderTokenList();
    loadTokenTxs();
  } catch (e) {
    $('tok-list').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

function renderTokenList() {
  if (_tokens.length === 0) {
    $('tok-list').innerHTML = '<div class="staging-empty">no tokens found on this network</div>';
    $('tok-count').textContent = '0';
    return;
  }
  $('tok-count').textContent = _tokens.length;
  var h = '';
  for (var i = 0; i < _tokens.length; i++) {
    var t = _tokens[i];
    var bal = t.balance || '0';
    var balCls = (bal === '0') ? 'token-zero' : 'token-balance';
    h += '<div class="token-card">';
    h += '<div class="token-header">';
    h += '<div><span class="token-symbol">' + escapeHtml(t.symbol) + '</span>';
    h += '<span class="token-name">' + escapeHtml(t.name) + '</span></div>';
    h += '<div class="' + balCls + '">' + fmtTokenCompact(bal, t.decimals) + ' ' + escapeHtml(t.symbol) + '</div>';
    h += '</div>';
    h += '<div class="token-row">';
    h += '<span class="mono gray">' + short(t.address) + '</span>';
    h += '</div>';
    h += '<div class="token-actions">';
    h += '<button class="token-btn" onclick="openTokenTransfer(' + i + ')">transfer</button>';
    h += '</div>';
    h += '</div>';
  }
  $('tok-list').innerHTML = h;
}

function openTokenTransfer(idx) {
  _selectedToken = _tokens[idx];
  $('tok-transfer-sym').textContent = _selectedToken.symbol;
  $('tok-to').value = '';
  $('tok-amount').value = '';
  clearResult('tok-transfer-result');
  $('tok-transfer').style.display = '';
  $('tok-to').focus();
}

function closeTokenTransfer() {
  $('tok-transfer').style.display = 'none';
  _selectedToken = null;
}

function parseUnits(humanStr, decimals) {
  var dec = parseInt(decimals) || 0;
  var s = String(humanStr).trim();
  if (!s || s === '0') return '';
  var neg = false;
  if (s[0] === '-') { neg = true; s = s.slice(1); }
  var parts = s.split('.');
  var intPart = parts[0].replace(/[^0-9]/g, '') || '0';
  var fracPart = parts.length > 1 ? parts[1].replace(/[^0-9]/g, '') : '';
  if (fracPart.length > dec) fracPart = fracPart.slice(0, dec);
  while (fracPart.length < dec) fracPart += '0';
  var raw = (intPart + fracPart).replace(/^0+/, '') || '0';
  if (raw === '0') return '';
  return neg ? '-' + raw : raw;
}

async function doTokenTransfer() {
  clearResult('tok-transfer-result');
  if (!_selectedToken) { showResult('tok-transfer-result', false, 'no token selected'); return; }
  var to = $('tok-to').value.trim();
  var humanAmt = $('tok-amount').value.trim();
  if (!validAddr(to)) { showResult('tok-transfer-result', false, 'invalid recipient address'); return; }
  if (!humanAmt || isNaN(parseFloat(humanAmt)) || parseFloat(humanAmt) <= 0) {
    showResult('tok-transfer-result', false, 'invalid amount'); return;
  }
  var rawAmount = parseUnits(humanAmt, _selectedToken.decimals);
  if (!rawAmount) { showResult('tok-transfer-result', false, 'invalid amount'); return; }
  if (!validateFee('tok-fee', 'call')) { feeError('tok-transfer-result', 'tok-fee', 'call'); return; }
  try {
    var tokBody = { token: _selectedToken.address, to: to, amount: rawAmount };
    var tokFee = $('tok-fee') ? $('tok-fee').value.trim() : '';
    if (tokFee) tokBody.ou = tokFee;
    var res = await api('POST', '/token/transfer', tokBody);
    var txHash = res.hash || res.tx_hash || '';
    showResult('tok-transfer-result', true,
      'sent ' + humanAmt + ' ' + _selectedToken.symbol + ' - tx: ' + txLink(txHash));
    $('tok-to').value = '';
    $('tok-amount').value = '';
    setTimeout(function() { loadTokens(); }, 2000);
  } catch (e) {
    showResult('tok-transfer-result', false, e.message);
  }
}

async function loadTokenTxs() {
  var el = $('tok-txs');
  if (!el) return;
  var gen = ++_tokTxGen;
  try {
    var filtered = [];
    var hist = await api('GET', '/history?limit=500&offset=0');
    if (gen !== _tokTxGen) return;
    var txs = hist.transactions || [];
    for (var i = 0; i < txs.length; i++) {
      var t = txs[i];
      if (t.op_type === 'call' && t.encrypted_data === 'transfer') filtered.push(t);
    }
    if (filtered.length === 0) {
      el.innerHTML = '<div class="staging-empty">no token transactions yet</div>';
      return;
    }
    await fetchMissingSymbols(filtered);
    var h = '<table class="desktop-table"><tr><th>hash</th><th>from</th><th>to</th><th class="col-amount">amount</th><th class="col-status">status</th><th class="col-time">time</th></tr>';
    var cards = '<div class="card-list">';
    for (var i = 0; i < filtered.length; i++) {
      h += txRow(filtered[i]);
      cards += txCardHtml(filtered[i]);
    }
    h += '</table>';
    cards += '</div>';
    el.innerHTML = h + cards;
  } catch(e) {
    el.innerHTML = '<div class="staging-empty">no token transactions yet</div>';
  }
}

function renderHistoryTxs(txs) {
  var h = '<table class="desktop-table"><tr><th>hash</th><th>from</th><th>to</th><th class="col-amount">amount</th><th class="col-status">status</th><th class="col-time">time</th></tr>';
  var cards = '<div class="card-list">';
  for (var i = 0; i < txs.length; i++) {
    h += txRow(txs[i]);
    cards += txCardHtml(txs[i]);
  }
  h += '</table>';
  cards += '</div>';
  $('history-list').innerHTML = h + cards;
}

async function loadHistory() {
  $('history-list').innerHTML = '<div class="loading">loading...</div>';
  $('history-more').innerHTML = '';
  loadTokenSymbols();
  try {
    var res = await api('GET', '/history?limit=' + _historyLimit + '&offset=' + _historyOffset);
    var txs = res.transactions || [];
    if (txs.length === 0 && _historyOffset === 0) {
      $('history-list').innerHTML = '<div class="staging-empty">no transactions yet</div>';
      return;
    }
    renderHistoryTxs(txs);
    if (txs.length >= _historyLimit) {
      $('history-more').innerHTML = '<button class="load-more" onclick="loadMoreHistory()">load more</button>';
    }
    fetchMissingSymbols(txs).then(function() { renderHistoryTxs(txs); });
  } catch (e) {
    $('history-list').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

function loadMoreHistory() {
  _historyOffset += _historyLimit;
  loadHistoryAppend();
}

async function loadHistoryAppend() {
  var btn = $('history-more').querySelector('button');
  if (btn) { btn.disabled = true; btn.textContent = 'loading...'; }
  try {
    var res = await api('GET', '/history?limit=' + _historyLimit + '&offset=' + _historyOffset);
    var txs = res.transactions || [];
    if (txs.length === 0) {
      $('history-more').innerHTML = '<div class="staging-empty">no more transactions</div>';
      return;
    }
    var tbl = $('history-list').querySelector('.desktop-table');
    var cardList = $('history-list').querySelector('.card-list');
    for (var i = 0; i < txs.length; i++) {
      if (tbl) {
        var row = tbl.insertRow(-1);
        row.innerHTML = txRow(txs[i]).replace(/<\/?tr>/g, '');
      }
      if (cardList) cardList.insertAdjacentHTML('beforeend', txCardHtml(txs[i]));
    }
    if (txs.length >= _historyLimit) {
      $('history-more').innerHTML = '<button class="load-more" onclick="loadMoreHistory()">load more</button>';
    } else {
      $('history-more').innerHTML = '';
    }
  } catch (e) {
    $('history-more').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

async function showKeys() {
  $('keys-table').innerHTML = '<div class="loading">loading...</div>';
  try {
    var res = await api('GET', '/keys');
    var h = '<table class="detail-table">';
    h += '<tr><td>address</td><td class="mono">' + (res.address || '') + '</td></tr>';
    h += '<tr><td>public key</td><td class="mono">' + (res.public_key || '') + '</td></tr>';
    h += '<tr><td>view pubkey</td><td class="mono">' + (res.view_pubkey || '-') + '</td></tr>';
    h += '<tr><td>private key</td><td id="privkey-cell" style="color:#8C9DB6;cursor:pointer" onclick="revealPrivateKeys()">****** (click to reveal)</td></tr>';
    h += '<tr><td>seed phrase</td><td id="seed-cell" style="color:#8C9DB6' + (res.has_master_seed ? ';cursor:pointer" onclick="revealPrivateKeys()' : '') + '">' + (res.has_master_seed ? '****** (click to reveal)' : 'not set - imported via private key only') + '</td></tr>';
    h += '</table>';
    $('keys-table').innerHTML = h;
  } catch (e) {
    $('keys-table').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

async function revealPrivateKeys() {
  var pin = await modalPrompt('reveal private keys', 'enter 6-digit PIN', { pin: true, btnText: 'reveal' });
  if (!pin || !/^\d{6}$/.test(pin)) return;
  try {
    var res = await api('POST', '/keys/private', { pin: pin });
    var pkCell = $('privkey-cell');
    if (pkCell) {
      pkCell.className = 'mono';
      pkCell.style.color = '';
      pkCell.style.cursor = '';
      pkCell.onclick = null;
      pkCell.textContent = res.private_key || '';
    }
    var seedCell = $('seed-cell');
    if (seedCell && res.mnemonic) {
      seedCell.className = 'mono';
      seedCell.style.color = '';
      seedCell.textContent = res.mnemonic;
    } else if (seedCell) {
      seedCell.textContent = 'not set - imported via private key only';
    }
  } catch (e) {
    showResult('keys-table', false, e.message);
  }
}

async function loadSettings() {
  try {
    var w = await api('GET', '/wallet');
    $('settings-rpc').value = w.rpc_url || 'http://46.101.86.250:8080';
    $('settings-explorer').value = w.explorer_url || 'https://octrascan.io';
    $('settings-bridge-signer').value = w.bridge_signer_url || 'https://relayer-002838819188.octra.network';
  } catch (e) {}
  loadAccountList();
}

async function loadAccountList() {
  var el = $('wallet-list');
  if (!el) return;
  try {
    var resp = await api('GET', '/wallet/accounts');
    var accounts = resp.accounts || [];
    if (accounts.length === 0) {
      el.innerHTML = '<div class="staging-empty">no accounts</div>';
      return;
    }
    var btnStyle = 'display:inline-block;width:80px;padding:8px;margin:0;background:#E5E9EF;border:none;border-top:1px solid #D0D7E2;border-bottom:1px solid #D0D7E2;margin-right:4px;color:#3B567F;font-family:Tahoma,arial,sans-serif;font-size:11px;font-weight:bold;letter-spacing:1px;cursor:pointer;text-align:center;text-transform:lowercase';
    var btnHover = 'onmouseenter="this.style.background=\'#D0D7E2\'" onmouseleave="this.style.background=\'#E5E9EF\'"';
    var html = '<table class="tx-table" style="width:100%"><tbody>';
    for (var i = 0; i < accounts.length; i++) {
      var a = accounts[i];
      var badge = a.active ? '<span style="color:#4CAF50;margin-right:4px">●</span>' : '';
      var hdLabel = '';
      if (a.hd) {
        if (a.parent_addr) {
          var short_parent = a.parent_addr.substring(0, 8) + '...' + a.parent_addr.slice(-4);
          hdLabel = ' <span style="color:#8C9DB6;font-size:11px">[HD #' + a.hd_index + ' from ' + short_parent + ']</span>';
        } else {
          hdLabel = ' <span style="color:#8C9DB6;font-size:11px">[HD]</span>';
        }
      }
      var name = a.name || 'unnamed';
      var escapedName = name.replace(/'/g, "\\'");
      html += '<tr>';
      html += '<td style="padding:6px 8px;vertical-align:middle">' + badge + '<b>' + name + '</b>' + hdLabel + '</td>';
      html += '<td class="mono" style="padding:6px 8px;font-size:11px;vertical-align:middle;word-break:break-all">' + a.addr + '</td>';
      html += '<td style="padding:6px 4px;text-align:right;white-space:nowrap;vertical-align:middle">';
      if (!a.active) {
        html += '<button style="' + btnStyle + '" ' + btnHover + ' onclick="doSwitchAccount(\'' + a.addr + '\')">switch</button>';
      }
      html += '<button style="' + btnStyle + '" ' + btnHover + ' onclick="doRenameAccount(\'' + a.addr + '\',\'' + escapedName + '\')">rename</button>';
      html += '</td></tr>';
    }
    html += '</tbody></table>';
    el.innerHTML = html;
    var actEl = $('wallet-actions');
    if (actEl) {
      var ah = '<div class="action-row" style="gap:6px;flex-wrap:wrap;align-items:center">';
      if (resp.has_master_seed) {
        var idx = resp.next_hd_index || 0;
        ah += '<button class="action-btn" onclick="doDeriveAccount()">derive #' + idx + '</button>';
        ah += '<span style="color:#8C9DB6;font-size:11px;margin:0 4px">or</span>';
      }
      ah += '<button class="action-btn" onclick="showImportAnother()">import another wallet</button>';
      ah += '</div>';
      actEl.innerHTML = ah;
    }
  } catch (e) {
    el.innerHTML = '<div class="staging-empty">could not load accounts</div>';
  }
}

var _modalPromptResolve = null;
var _modalPromptBtnText = '';

function modalPrompt(title, label, opts) {
  opts = opts || {};
  return new Promise(function(resolve) {
    _modalPromptResolve = resolve;
    _modalPromptBtnText = opts.btnText || 'ok';
    hideAllModalPanels();
    $('modal-sub').textContent = title;
    $('modal-result').innerHTML = '';
    if (opts.pin) {
      $('modal-pin').style.display = 'block';
      $('modal-pin-input').value = '';
      $('pin-back-btn').style.display = '';
      var unlockBtn = $('modal-pin').querySelector('.action-btn');
      if (unlockBtn) unlockBtn.textContent = _modalPromptBtnText;
      $('modal-pin-input').focus();
      $('modal-overlay').style.display = 'flex';
    } else {
      var h = '<div class="form-row"><label>' + label + '</label>';
      h += '<input type="text" id="modal-prompt-input"';
      if (opts.placeholder) h += ' placeholder="' + opts.placeholder + '"';
      h += ' autocomplete="off"></div>';
      h += '<div class="action-row">';
      h += '<button class="action-btn" id="modal-prompt-ok">ok</button>';
      h += '<button class="action-btn" style="background:#8C9DB6" id="modal-prompt-cancel">cancel</button>';
      h += '</div>';
      $('modal-result').innerHTML = h;
      $('modal-overlay').style.display = 'flex';
      $('modal-prompt-input').focus();
      $('modal-prompt-ok').onclick = function() {
        var val = $('modal-prompt-input').value;
        _modalPromptResolve = null;
        $('modal-result').innerHTML = '';
        $('modal-overlay').style.display = 'none';
        resolve(val);
      };
      $('modal-prompt-cancel').onclick = function() {
        _modalPromptResolve = null;
        $('modal-result').innerHTML = '';
        $('modal-overlay').style.display = 'none';
        resolve(null);
      };
      $('modal-prompt-input').onkeydown = function(e) {
        if (e.key === 'Enter') $('modal-prompt-ok').click();
        if (e.key === 'Escape') $('modal-prompt-cancel').click();
      };
    }
  });
}

async function doSwitchAccount(addr) {
  var pin = await modalPrompt('switch account', 'enter 6-digit PIN', { pin: true, btnText: 'switch' });
  if (!pin || !/^\d{6}$/.test(pin)) return;
  clearResult('wallet-mgmt-result');
  try {
    await api('POST', '/wallet/switch', { addr: addr, pin: pin });
    showResult('wallet-mgmt-result', true, 'switched account');
    ['send-result','enc-result','dec-result','fhe-result','ct-compile-result','ct-deploy-result','ct-call-result','ct-info-result','ct-verify-result','tok-transfer-result','settings-result'].forEach(function(id) { clearResult(id); });
    var sl = $('stealth-log'); if (sl) sl.remove();
    var so = $('stealth-outputs'); if (so) so.innerHTML = '';
    _pendingClaimIds = {};
    _cachedBal = null;
    _encryptedBalanceRaw = 0;
    _unclaimedCount = 0;
    _historyOffset = 0;
    _tokens = [];
    _tokensLoaded = false;
    _fees = {};
    await loadWalletInfo();
    loadAccountList();
    fetchBalance();
    fetchFees();
    switchView('dashboard');
  } catch (e) {
    showResult('wallet-mgmt-result', false, e.message);
  }
}

async function doRenameAccount(addr, currentName) {
  var name = await modalPrompt('rename account', 'new name', { placeholder: currentName || 'my wallet' });
  if (!name || !name.trim()) return;
  clearResult('wallet-mgmt-result');
  try {
    await api('POST', '/wallet/rename', { addr: addr, name: name.trim() });
    showResult('wallet-mgmt-result', true, 'renamed');
    loadAccountList();
  } catch (e) {
    showResult('wallet-mgmt-result', false, e.message);
  }
}

async function doDeriveAccount() {
  if (!_hasMasterSeed) return;
  var pin = await modalPrompt('derive new address', 'enter 6-digit PIN', { pin: true });
  if (!pin || !/^\d{6}$/.test(pin)) return;
  var name = await modalPrompt('derive new address', 'name for new account (optional)', { placeholder: 'trading' });
  if (name === null) return;
  clearResult('wallet-mgmt-result');
  try {
    var resp = await api('POST', '/wallet/derive', { pin: pin, name: (name || '').trim() });
    showResult('wallet-mgmt-result', true, 'derived: ' + (resp.address || '').substring(0, 16) + '...');
    loadAccountList();
  } catch (e) {
    showResult('wallet-mgmt-result', false, e.message);
  }
}

var _importFromSettings = false;

function showImportAnother() {
  _pendingAction = null;
  _pendingPriv = '';
  _pendingMnemonic = '';
  _importFromSettings = true;
  hideAllModalPanels();
  $('modal-sub').textContent = 'import additional wallet';
  $('modal-import').style.display = 'block';
  switchImportTab('seed');
  $('modal-overlay').style.display = 'flex';
}

async function doSaveSettings() {
  clearResult('settings-result');
  var rpc = $('settings-rpc').value.trim();
  var explorer = $('settings-explorer').value.trim();
  var bridgeSigner = $('settings-bridge-signer').value.trim();
  if (!rpc) { showResult('settings-result', false, 'rpc url required'); return; }
  try {
    var resp = await api('POST', '/settings', { rpc_url: rpc, explorer_url: explorer, bridge_signer_url: bridgeSigner });
    if (explorer) _explorerUrl = explorer.replace(/\/+$/, '');
    try { _rpcHost = new URL(rpc).hostname; } catch(e) { _rpcHost = rpc; }
    if (resp && resp.cache_cleared) {
      _cachedBal = null;
      _historyOffset = 0;
      _tokens = [];
      _tokensLoaded = false;
      _fees = {};
      _encryptedBalanceRaw = 0;
      _unclaimedCount = 0;
      _tokenSymbols = {};
      _tokenDecimals = {};
      fetchBalance();
      if (document.querySelector('.nav-tabs a.active[data-view="dashboard"]'))
        loadDashboard();
      showResult('settings-result', true, 'saved · cache cleared');
    } else {
      showResult('settings-result', true, 'saved');
    }
  } catch (e) {
    showResult('settings-result', false, e.message);
  }
}

async function doChangePin() {
  clearResult('pin-change-result');
  var cur = $('pin-current').value;
  var np = $('pin-new').value;
  var nc = $('pin-confirm-new').value;
  if (!/^\d{6}$/.test(cur)) { showResult('pin-change-result', false, 'current PIN must be 6 digits'); return; }
  if (!/^\d{6}$/.test(np)) { showResult('pin-change-result', false, 'new PIN must be 6 digits'); return; }
  if (np !== nc) { showResult('pin-change-result', false, 'PINs do not match'); return; }
  if (cur === np) { showResult('pin-change-result', false, 'new PIN must be different'); return; }
  try {
    await api('POST', '/wallet/change-pin', { current_pin: cur, new_pin: np });
    showResult('pin-change-result', true, 'PIN changed successfully');
    $('pin-current').value = '';
    $('pin-new').value = '';
    $('pin-confirm-new').value = '';
  } catch (e) {
    showResult('pin-change-result', false, e.message);
  }
}

var _pendingAction = null;
var _pendingPriv = '';
var _pendingMnemonic = '';
var _importMode = 'seed';

function hideAllModalPanels() {
  $('modal-btns').style.display = 'none';
  $('modal-import').style.display = 'none';
  $('modal-pin').style.display = 'none';
  $('modal-pin-setup').style.display = 'none';
  $('modal-mnemonic-show').style.display = 'none';
  $('modal-result').innerHTML = '';
}

function showPinEntry(showBack) {
  hideAllModalPanels();
  $('modal-pin').style.display = 'block';
  $('modal-pin-input').value = '';
  var backBtn = $('pin-back-btn');
  if (backBtn) backBtn.style.display = showBack ? '' : 'none';
  $('modal-pin-input').focus();
}

function showPinSetup(action) {
  _pendingAction = action;
  hideAllModalPanels();
  $('modal-pin-setup').style.display = 'block';
  $('modal-pin-new').value = '';
  $('modal-pin-confirm').value = '';
  $('modal-pin-new').focus();
}

function modalShowImport() {
  hideAllModalPanels();
  $('modal-import').style.display = 'block';
  switchImportTab('seed');
}

function switchImportTab(mode) {
  _importMode = mode;
  var tabs = document.querySelectorAll('.import-tab');
  tabs.forEach(function(t) { t.classList.remove('active'); });
  if (mode === 'seed') {
    tabs[0].classList.add('active');
    $('import-seed').style.display = 'block';
    $('import-key').style.display = 'none';
  } else {
    tabs[1].classList.add('active');
    $('import-seed').style.display = 'none';
    $('import-key').style.display = 'block';
  }
}

function modalBack() {
  _selectedUnlockAddr = '';
  _selectedUnlockFile = '';
  hideAllModalPanels();
  if (_importFromSettings) {
    _importFromSettings = false;
    $('modal-overlay').style.display = 'none';
    return;
  }
  init();
}

function modalBackFromPin() {
  if (_modalPromptResolve) {
    var cb = _modalPromptResolve;
    _modalPromptResolve = null;
    var unlockBtn = $('modal-pin').querySelector('.action-btn');
    if (unlockBtn) unlockBtn.textContent = 'unlock';
    hideAllModalPanels();
    $('modal-overlay').style.display = 'none';
    cb(null);
    return;
  }
  _pendingAction = null;
  _pendingPriv = '';
  _pendingMnemonic = '';
  _selectedUnlockAddr = '';
  _selectedUnlockFile = '';
  hideAllModalPanels();
  init();
}

function modalCreate() {
  showPinSetup('create');
  $('modal-sub').textContent = 'set a 6-digit PIN for your new wallet';
}

function modalDoImport() {
  if (_importMode === 'seed') {
    var mn = $('modal-mnemonic').value.trim().toLowerCase();
    if (!mn) {
      $('modal-result').innerHTML = '<div class="result-msg result-error">seed phrase required</div>';
      return;
    }
    var words = mn.split(/\s+/);
    if (words.length !== 12 && words.length !== 24) {
      $('modal-result').innerHTML = '<div class="result-msg result-error">seed phrase must be 12 or 24 words</div>';
      return;
    }
    _pendingMnemonic = words.join(' ');
    _pendingPriv = '';
    $('modal-mnemonic').value = '';
  } else {
    var priv = $('modal-privkey').value.trim();
    if (!priv) {
      $('modal-result').innerHTML = '<div class="result-msg result-error">private key required</div>';
      return;
    }
    _pendingPriv = priv;
    _pendingMnemonic = '';
    $('modal-privkey').value = '';
  }
  showPinSetup('import');
  $('modal-sub').textContent = 'set a 6-digit PIN for your wallet';
}

function showMnemonicWords(mnemonic) {
  var words = mnemonic.split(' ');
  var html = '';
  for (var i = 0; i < words.length; i++) {
    html += '<div class="mnemonic-word"><span class="mw-num">' + (i+1) + '</span>' + words[i] + '</div>';
  }
  $('mnemonic-words').innerHTML = html;
  $('mnemonic-confirm-check').checked = false;
  $('mnemonic-continue-btn').disabled = true;
  $('mnemonic-confirm-check').onchange = function() {
    $('mnemonic-continue-btn').disabled = !this.checked;
  };
}

function modalMnemonicDone() {
  $('mnemonic-words').innerHTML = '';
  $('modal-overlay').style.display = 'none';
  loadWalletInfo();
  startRefreshTimer();
}

async function modalUnlock() {
  var pin = $('modal-pin-input').value;
  if (!/^\d{6}$/.test(pin)) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">PIN must be exactly 6 digits</div>';
    return;
  }
  if (_modalPromptResolve) {
    var cb = _modalPromptResolve;
    _modalPromptResolve = null;
    var unlockBtn = $('modal-pin').querySelector('.action-btn');
    if (unlockBtn) unlockBtn.textContent = 'unlock';
    hideAllModalPanels();
    $('modal-overlay').style.display = 'none';
    cb(pin);
    return;
  }
  $('modal-result').innerHTML = '<div class="loading">unlocking...</div>';
  try {
    var unlockBody = { pin: pin };
    if (_selectedUnlockAddr) unlockBody.addr = _selectedUnlockAddr;
    if (_selectedUnlockFile) unlockBody.file = _selectedUnlockFile;
    await api('POST', '/wallet/unlock', unlockBody);
    _selectedUnlockAddr = '';
    _selectedUnlockFile = '';
    $('modal-overlay').style.display = 'none';
    await loadWalletInfo();
    startRefreshTimer();
  } catch (e) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">' + e.message + '</div>';
    $('modal-pin-input').value = '';
    $('modal-pin-input').focus();
  }
}

async function modalFinishSetup() {
  var pin = $('modal-pin-new').value;
  var confirm = $('modal-pin-confirm').value;
  if (!/^\d{6}$/.test(pin)) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">PIN must be exactly 6 digits</div>';
    return;
  }
  if (pin !== confirm) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">PINs do not match</div>';
    $('modal-pin-confirm').value = '';
    return;
  }
  $('modal-result').innerHTML = '<div class="loading">processing...</div>';
  try {
    if (_pendingAction === 'create') {
      var resp = await api('POST', '/wallet/create', { pin: pin });
      if (resp.mnemonic) {
        hideAllModalPanels();
        $('modal-sub').textContent = 'your seed phrase';
        $('modal-mnemonic-show').style.display = 'block';
        showMnemonicWords(resp.mnemonic);
        return;
      }
    } else if (_pendingAction === 'import') {
      var importBody = { pin: pin };
      if (_pendingMnemonic) {
        importBody.mnemonic = _pendingMnemonic;
        _pendingMnemonic = '';
      } else {
        importBody.priv = _pendingPriv;
        _pendingPriv = '';
      }
      var resp = await api('POST', '/wallet/import', importBody);
      if (resp.switched === false) {
        $('modal-overlay').style.display = 'none';
        showResult('wallet-mgmt-result', true, 'imported: ' + (resp.address || '').substring(0, 16) + '...');
        loadAccountList();
        return;
      }
    } else if (_pendingAction === 'migrate') {
      await api('POST', '/wallet/unlock', { pin: pin });
    }
    $('modal-overlay').style.display = 'none';
    await loadWalletInfo();
    startRefreshTimer();
  } catch (e) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">' + e.message + '</div>';
  }
}

async function loadWalletInfo() {
  try {
    var w = await api('GET', '/wallet');
    _walletAddr = w.address || w.addr || '';
    if (w.explorer_url) _explorerUrl = w.explorer_url.replace(/\/+$/, '');
    if (w.rpc_url) try { _rpcHost = new URL(w.rpc_url).hostname; } catch(e) { _rpcHost = w.rpc_url; }
    _hasMasterSeed = !!w.has_master_seed;
    $('hdr-addr').innerHTML = '<span class="mono">' + _walletAddr + '</span>';
    $('hdr-logout').style.display = '';
    $('hdr-dev').style.display = '';
    $('hdr-apps').style.display = '';
    fetchFees();
    loadDashboard();
  } catch (e) {
    $('hdr-addr').textContent = 'error loading wallet';
    $('hdr-status').textContent = 'error';
    $('hdr-status').className = 'right error';
  }
}

async function doLogout() {
  try { await api('POST', '/wallet/lock', {}); } catch (e) {}
  if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; }
  _walletAddr = '';
  _cachedBal = null;
  _encryptedBalanceRaw = 0;
  _hasMasterSeed = false;
  $('hdr-logout').style.display = 'none';
  $('hdr-dev').style.display = 'none';
  $('hdr-apps').style.display = 'none';
  $('hdr-addr').textContent = 'locked';
  $('hdr-status').textContent = 'locked';
  $('hdr-status').className = 'right';
  switchView('dashboard');
  init();
}

function startRefreshTimer() {
  if (_refreshTimer) return;
  bgStealthScan();
  _refreshTimer = setInterval(function() {
    fetchBalance();
    bgStealthScan();
    fetchFees();
    var dash = $('view-dashboard');
    if (dash && dash.classList.contains('active')) loadDashboard();
  }, 15000);
}


var _selectedUnlockAddr = '';
var _selectedUnlockFile = '';

function showAccountPicker(wallets) {
  hideAllModalPanels();
  $('modal-sub').textContent = 'select account';
  var html = '<div style="margin:10px 0;max-height:300px;overflow-y:auto">';
  for (var i = 0; i < wallets.length; i++) {
    var a = wallets[i];
    var hasAddr = a.addr && a.addr.length > 0;
    var name = a.name || (hasAddr ? 'wallet' : a.file.replace('data/', ''));
    var sub = hasAddr
      ? a.addr.substring(0, 12) + '...' + a.addr.substring(a.addr.length - 6)
      : a.file;
    var hdTag = a.hd ? ' · hd' : '';
    var dataAttr = hasAddr
      ? 'data-addr="' + a.addr + '"'
      : 'data-file="' + a.file + '"';
    html += '<div class="account-card" ' + dataAttr + ' onclick="pickWallet(this)" style="cursor:pointer;padding:10px 12px;margin:6px 0;border:1px solid #3B567F;transition:background 0.15s,color 0.15s"';
    html += ' onmouseenter="this.style.background=\'#2A3F5F\';this.style.color=\'#fff\'" onmouseleave="this.style.background=\'\';this.style.color=\'\'">';
    html += '<div style="font-weight:600">' + name + '<span style="color:#8C9DB6;font-size:11px">' + hdTag + '</span></div>';
    html += '<div class="mono" style="font-size:12px;color:#8C9DB6;margin-top:2px">' + sub + '</div>';
    html += '</div>';
  }
  html += '</div>';
  html += '<div style="margin-top:8px;text-align:center">';
  html += '<a href="#" style="color:#8C9DB6;font-size:12px" onclick="showImportOptions();return false">+ import or create new wallet</a>';
  html += '</div>';
  $('modal-result').innerHTML = html;
  $('modal-overlay').style.display = 'flex';
}

function pickWallet(el) {
  _selectedUnlockAddr = el.getAttribute('data-addr') || '';
  _selectedUnlockFile = el.getAttribute('data-file') || '';
  $('modal-sub').textContent = 'enter PIN to unlock';
  $('modal-result').innerHTML = '';
  showPinEntry(true);
}

function showImportOptions() {
  hideAllModalPanels();
  $('modal-sub').textContent = 'add wallet';
  $('modal-btns').style.display = 'flex';
  $('modal-result').innerHTML = '';
}

async function init() {
  try {
    var st = await api('GET', '/wallet/status');
    if (st.loaded) {
      await loadWalletInfo();
      startRefreshTimer();
      return;
    }
    if (st.has_legacy) {
      $('modal-sub').textContent = 'migrating wallet - set a PIN';
      showPinSetup('migrate');
      $('modal-overlay').style.display = 'flex';
      return;
    }
    var wallets = st.wallets || [];
    if (wallets.length === 0) {
      $('modal-sub').textContent = 'no wallet found';
      $('modal-btns').style.display = 'flex';
      $('modal-overlay').style.display = 'flex';
      return;
    }
    if (wallets.length === 1 && wallets[0].addr) {
      _selectedUnlockAddr = wallets[0].addr;
      _selectedUnlockFile = '';
      $('modal-sub').textContent = 'enter PIN to unlock';
      showPinEntry();
      $('modal-overlay').style.display = 'flex';
      return;
    }
    showAccountPicker(wallets);
  } catch (e) {
    $('modal-overlay').style.display = 'flex';
  }
}

$('modal-pin-input').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') modalUnlock();
});
$('modal-pin-confirm').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') modalFinishSetup();
});

initEditor();
init();