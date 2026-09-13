import assert from 'node:assert/strict';
import test from 'node:test';
import { LatestRequest, mergeById, mediaPickerExtensions, normalizeMediaSelection, snapshotProjectCommand, SelectionMailbox } from '../src/lib/workflow-state.ts';
import { deferred } from './component-harness.mjs';

test('only the most recent request can commit', () => {
  const requests = new LatestRequest(); const first = requests.begin(); const last = requests.begin();
  assert.equal(first(), false); assert.equal(last(), true);
});
test('invalidation rejects pending work', () => {
  const requests = new LatestRequest(); const pending = requests.begin(); requests.invalidate();
  assert.equal(pending(), false); assert.equal(requests.begin()(), true);
});
test('disposal also rejects queued callbacks that begin later', () => {
  const requests = new LatestRequest(); const pending = requests.begin(); requests.dispose();
  assert.equal(pending(), false); assert.equal(requests.begin()(), false);
});
test('merging deduplicates page boundaries and repeated IDs within a page', () => {
  const first = [{id:'a'}], next = [{id:'a'}, {id:'b'}, {id:'b'}];
  assert.deepEqual(mergeById(first,next), [{id:'a'}, {id:'b'}]);
  assert.equal(first.length, 1); assert.equal(next.length, 3);
});
test('empty pages preserve earlier results', () => { assert.deepEqual(mergeById([{id:'a'}],[]), [{id:'a'}]); });
test('desktop file filters use extensions, Android filters use MIME types', () => {
  assert.deepEqual(mediaPickerExtensions(false), ['jpg','jpeg','png','mp4','webm']);
  assert.deepEqual(mediaPickerExtensions(true), ['image/jpeg','image/png','video/mp4','video/webm']);
});
test('filter arrays cannot mutate future dialogs', () => { mediaPickerExtensions(false).push('exe'); assert.equal(mediaPickerExtensions(false).includes('exe'), false); });
test('media selection handles cancellation and deduplicates source paths', () => {
  assert.equal(normalizeMediaSelection(null), null); assert.equal(normalizeMediaSelection([]), null);
  const result=normalizeMediaSelection(['a','a','b']); assert.deepEqual(result,['a','b']); assert.ok(Object.isFrozen(result));
});
test('media selection enforces the native command bounds before submission', () => {
  assert.equal(normalizeMediaSelection(Array.from({length:100},(_,i)=>String(i))).length,100);
  assert.throws(()=>normalizeMediaSelection(Array.from({length:101},(_,i)=>String(i))),/100/);
  assert.throws(()=>normalizeMediaSelection('x'.repeat(16385)),/invalid/);
  assert.throws(()=>normalizeMediaSelection(''),/invalid/);
});
test('command snapshot is immutable and does not change during reauthentication', () => {
  const form={id:'a',environment:'dev',program:' node ',argumentsText:'run.js'};
  const snapshot=snapshotProjectCommand(form); form.id='b'; form.environment='prod'; form.program='other';
  assert.deepEqual(snapshot,{id:'a',environment:'dev',program:'node',args:['run.js']});
  assert.ok(Object.isFrozen(snapshot)); assert.ok(Object.isFrozen(snapshot.args));
});
test('arguments preserve literal whitespace and shell characters and handle CRLF', () => {
  assert.deepEqual(snapshotProjectCommand({id:'a',environment:'dev',program:'node',argumentsText:'script.js\r\n  literal  \r\n\r\n$(not-shell)\n--name=a b\n'}).args,
    ['script.js','  literal  ','$(not-shell)','--name=a b']);
});
test('picker selection survives screen unsubscribe and can be explicitly resumed', async () => {
  const mailbox=new SelectionMailbox(), picker=deferred(); let last;
  const unsubscribe=mailbox.subscribe((state)=>{last=state;});
  const choosing=mailbox.choose(()=>picker.promise); assert.equal(last.selecting,true); unsubscribe();
  picker.resolve(['content://picked']); await choosing;
  mailbox.subscribe((state)=>{last=state;}); assert.deepEqual(last.value,['content://picked']); assert.equal(last.selecting,false);
});
test('only one picker may run, and an existing selection cannot be overwritten', async () => {
  const mailbox=new SelectionMailbox(), picker=deferred(); let calls=0;
  const choosing=mailbox.choose(()=>{calls++;return picker.promise;});
  await mailbox.choose(async()=>{calls++;return 'other';}); picker.resolve('chosen'); await choosing;
  await mailbox.choose(async()=>{calls++;return 'other';}); assert.equal(calls,1); assert.equal(mailbox.current.value,'chosen');
});
test('picker errors are surfaced and do not leave selection permanently busy', async () => {
  const mailbox=new SelectionMailbox(); await mailbox.choose(async()=>{throw new Error('denied');});
  assert.match(mailbox.current.error,/denied/); assert.equal(mailbox.current.selecting,false);
  await mailbox.choose(async()=>null); assert.equal(mailbox.current.error,''); assert.equal(mailbox.current.value,null);
});
test('claim prevents duplicate imports across screen lifetimes and blocks discard', async () => {
  const mailbox=new SelectionMailbox(); const sources=['a']; await mailbox.choose(async()=>sources);
  assert.equal(mailbox.claim(sources),true); assert.equal(mailbox.claim(sources),false);
  mailbox.clear(); assert.equal(mailbox.current.value,sources);
  mailbox.release(sources); assert.equal(mailbox.claim(sources),true);
  mailbox.consume(sources); assert.equal(mailbox.current.value,null); assert.equal(mailbox.current.processing,false);
});
test('late completions cannot consume or release a newer selection', async () => {
  const mailbox=new SelectionMailbox(); await mailbox.choose(async()=>'old'); mailbox.consume('old');
  await mailbox.choose(async()=>'new'); mailbox.claim('new'); mailbox.consume('old'); mailbox.release('old');
  assert.equal(mailbox.current.value,'new'); assert.equal(mailbox.current.processing,true);
});
