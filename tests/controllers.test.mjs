import assert from 'node:assert/strict';
import test from 'node:test';
import { controller, deferred } from './component-harness.mjs';
import { SelectionMailbox } from '../src/lib/workflow-state.ts';
const page=(id,cursor=null)=>({items:[{id}],nextCursor:cursor});
const empty=()=>({items:[],nextCursor:null});
const video={id:'v',mimeType:'video/mp4'};

for (const name of ['GalleryView','PasswordView']) {
  const active = name==='GalleryView'?'galleryPage':'credentialPage';
  const trash = name==='GalleryView'?'galleryTrashPage':'credentialTrashPage';
  test(`${name}: refresh starts a new page while the old page is pending`, async () => {
    const old=deferred(), fresh=deferred(); let calls=0;
    const c=controller(name,{vaultApi:{[active]:()=>++calls===1?old.promise:fresh.promise}});
    const first=c.loadMore(); const refresh=c.refresh();
    assert.equal(calls,2); old.resolve(page('old')); await first;
    assert.deepEqual(c.state().items,[]); assert.equal(c.state().loading,true);
    fresh.resolve(page('fresh')); await refresh;
    assert.deepEqual(c.state().items,[{id:'fresh'}]); assert.equal(c.state().loading,false);
  });
  test(`${name}: switching to trash rejects late active-page results`, async () => {
    const old=deferred(); const c=controller(name,{vaultApi:{[active]:()=>old.promise,[trash]:async()=>page('trash')}});
    const first=c.loadMore(); await c.switchMode('trash'); old.resolve(page('active')); await first;
    const items=name==='GalleryView'?c.state().trashItems:c.state().items;
    assert.deepEqual(items,[{id:'trash'}]); assert.equal(c.state().mode,'trash');
  });
  test(`${name}: stale page errors do not overwrite newer success`, async () => {
    const old=deferred();let calls=0;
    const c=controller(name,{vaultApi:{[active]:()=>++calls===1?old.promise:Promise.resolve(page('fresh'))}});
    const first=c.loadMore();await c.refresh();old.reject(new Error('old error'));await first;
    assert.equal(c.state().error,'');assert.deepEqual(c.state().items,[{id:'fresh'}]);
  });
  test(`${name}: a page failure remains retryable at the same cursor`, async () => {
    let calls=0;const cursors=[];
    const c=controller(name,{vaultApi:{[active]:async(cursor)=>{cursors.push(cursor);if(++calls===1)throw new Error('retry');return page('ok');}}});
    await c.loadMore();assert.equal(c.state().loading,false);assert.equal(c.state().hasMore,true);
    await c.loadMore();assert.deepEqual(cursors,[null,null]);assert.equal(c.state().error,'');
  });
  test(`${name}: dispose prevents late page updates and queued additional loads`, async () => {
    const pending=deferred();let calls=0;
    const c=controller(name,{vaultApi:{[active]:()=>{calls++;return pending.promise;}}});
    const loading=c.loadMore();c.destroy();pending.resolve(page('secret'));await loading;await c.loadMore();
    assert.deepEqual(c.state().items,[]);assert.equal(calls,1);
  });
  test(`${name}: native confirmation rejection is caught and releases action state`, async () => {
    let mutations=0;
    const c=controller(name,{confirm:async()=>{throw new Error('dialog failed');}});
    await c.mutate(async()=>{mutations++;},...(name==='GalleryView'?['done','warning']:['warning']));
    assert.equal(mutations,0);assert.equal(c.state().actionBusy,false);assert.match(c.state().error,/dialog failed/);
  });
}

test('GalleryView: closing and reopening the same video revokes the obsolete stream', async()=>{
  const old=deferred(),fresh=deferred(),closed=[];let calls=0;
  const c=controller('GalleryView',{vaultApi:{openMediaStream:()=>++calls===1?old.promise:fresh.promise,closeMediaStream:async(token)=>{closed.push(token);}}});
  const a=c.openItem(video);c.closeViewer();const b=c.openItem(video);
  fresh.resolve({token:'new',url:'new-url'});await b;old.resolve({token:'old',url:'old-url'});await a;
  assert.equal(c.state().videoToken,'new');assert.equal(c.state().videoUrl,'new-url');assert.deepEqual(closed,['old']);
  c.destroy();assert.deepEqual(closed,['old','new']);
});
test('GalleryView: stream created after destruction is immediately revoked', async()=>{
  const pending=deferred(),closed=[];
  const c=controller('GalleryView',{vaultApi:{openMediaStream:()=>pending.promise,closeMediaStream:async(token)=>{closed.push(token);}}});
  const opened=c.openItem(video);c.destroy();pending.resolve({token:'late',url:'secret-url'});await opened;
  assert.deepEqual(closed,['late']);assert.equal(c.state().videoUrl,'');
});
test('GalleryView: picker return after lock is retained without importing from the destroyed screen', async()=>{
  const picker=deferred(),mailbox=new SelectionMailbox();let imports=0;
  const c=controller('GalleryView',{open:()=>picker.promise,pendingMediaSelection:mailbox,vaultApi:{importMedia:async()=>{imports++;}}});
  const choosing=c.importFiles();c.destroy();picker.resolve(['content://selected']);await choosing;
  assert.deepEqual(mailbox.current.value,['content://selected']);assert.equal(imports,0);
});
test('GalleryView: vault locked after selection preserves sources for explicit retry', async()=>{
  const mailbox=new SelectionMailbox();await mailbox.choose(async()=>['a']);let imports=0;
  const c=controller('GalleryView',{pendingMediaSelection:mailbox,vaultApi:{status:async()=>({locked:true}),importMedia:async()=>{imports++;}}});
  await c.importPending();assert.equal(imports,0);assert.deepEqual(mailbox.current.value,['a']);assert.equal(mailbox.current.processing,false);
});
test('GalleryView: a new screen cannot duplicate an import running across a lock', async()=>{
  const mailbox=new SelectionMailbox(),pending=deferred();await mailbox.choose(async()=>['a']);let imports=0;
  const api={status:async()=>({locked:false}),importMedia:()=>{imports++;return pending.promise;},galleryPage:async()=>empty()};
  const old=controller('GalleryView',{pendingMediaSelection:mailbox,vaultApi:api});const running=old.importPending();
  await Promise.resolve();assert.equal(imports,1);old.destroy();
  const fresh=controller('GalleryView',{pendingMediaSelection:mailbox,vaultApi:api});await fresh.importPending();assert.equal(imports,1);
  pending.resolve({items:[{id:'imported',sourceIndex:0}],sourceRemovalEnabled:false});await running;
  assert.equal(mailbox.current.value,null);assert.equal(mailbox.current.processing,false);
});
test('PasswordView: new credential cancels an earlier pending detail selection', async()=>{
  const detail=deferred();const c=controller('PasswordView',{vaultApi:{credentialDetail:()=>detail.promise}});
  const pending=c.openItem({id:'old'});c.addNew();detail.resolve({id:'old',password:'old-secret'});await pending;
  assert.equal(c.state().editing,null);assert.equal(c.state().editorOpen,true);
});
test('PasswordView: rapid selection displays only the most recent detail', async()=>{
  const old=deferred();const c=controller('PasswordView',{vaultApi:{credentialDetail:(id)=>id==='a'?old.promise:Promise.resolve({id})}});
  const pending=c.openItem({id:'a'});await c.openItem({id:'b'});old.resolve({id:'a'});await pending;
  assert.equal(c.state().editing.id,'b');
});
test('PasswordView: closing the editor prevents a pending detail from reopening it', async()=>{
  const detail=deferred();const c=controller('PasswordView',{vaultApi:{credentialDetail:()=>detail.promise}});
  const pending=c.openItem({id:'a'});c.closeEditor();detail.resolve({id:'a'});await pending;
  assert.equal(c.state().editing,null);assert.equal(c.state().editorOpen,false);
});
test('ProjectView: new environment check starts while old one is pending and cannot be overwritten', async()=>{
  const old=deferred(),fresh=deferred(),calls=[];
  const c=controller('ProjectView',{vaultApi:{projectEnvironmentStatus:(id,environment)=>{calls.push([id,environment]);return environment==='dev'?old.promise:fresh.promise;}}});
  c.set({selectedProjectId:'p',selectedEnvironment:'dev'});const a=c.refreshEnvironmentStatus();
  c.set({selectedEnvironment:'prod'});const b=c.environmentChanged();assert.deepEqual(calls,[['p','dev'],['p','prod']]);
  old.resolve({environment:'dev'});await a;assert.equal(c.state().environmentStatus,null);assert.equal(c.state().statusBusy,true);
  fresh.resolve({environment:'prod'});await b;assert.equal(c.state().environmentStatus.environment,'prod');assert.equal(c.state().statusBusy,false);
});
test('ProjectView: refreshing the registry retains the selected environment', async()=>{
  const c=controller('ProjectView',{vaultApi:{projectList:async()=>[{id:'p',environments:['dev','prod']}],projectEnvironmentStatus:async(id,environment)=>({id,environment})}});
  c.set({selectedProjectId:'p',selectedEnvironment:'prod'});await c.loadProjects();assert.equal(c.state().selectedEnvironment,'prod');
});
test('ProjectView: launch snapshots target before authentication and prevents duplicate execution', async()=>{
  const auth=deferred(),calls=[];
  const c=controller('ProjectView',{vaultApi:{reauthenticate:()=>auth.promise,runProjectCommand:async(...args)=>{calls.push(args);return{pid:42,injectedKeys:[]};}}});
  c.set({selectedProjectId:'a',selectedEnvironment:'dev',program:' node ',argumentsText:'run.js\n  literal  ',reauthPassword:'test-password'});
  const running=c.launchCommand();assert.equal(c.state().reauthPassword,'');
  c.set({selectedProjectId:'b',selectedEnvironment:'prod',program:'other',argumentsText:'other.js',reauthPassword:'another-password'});
  await c.launchCommand();auth.resolve({locked:false});await running;
  assert.deepEqual(calls,[['a','dev','node',['run.js','  literal  ']]]);assert.equal(c.state().busy,false);
});
test('ProjectView: locking during password confirmation prevents the later launch', async()=>{
  const auth=deferred();let launches=0;
  const c=controller('ProjectView',{vaultApi:{reauthenticate:()=>auth.promise,runProjectCommand:async()=>{launches++;}}});
  c.set({selectedProjectId:'a',selectedEnvironment:'dev',reauthPassword:'test-password'});
  const running=c.launchCommand();c.destroy();auth.resolve({locked:false});await running;assert.equal(launches,0);
});
test('ProjectView: registration consumes the chosen path even when inspection canonicalizes it', async()=>{
  const mailbox=new SelectionMailbox();await mailbox.choose(async()=>'/chosen/link');
  const c=controller('ProjectView',{pendingProjectSelection:mailbox,vaultApi:{registerProject:async()=>({id:'p',name:'project'}),projectList:async()=>[]}});
  c.set({inspection:{root:'/canonical/root'},registrationName:'project'});await c.registerProject();
  assert.equal(mailbox.current.value,null);assert.equal(mailbox.current.processing,false);
});
