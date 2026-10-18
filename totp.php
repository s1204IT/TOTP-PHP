<?php

declare(strict_types=1);
require 'lib.php';

header('Cache-Control: no-store');

function h(string $s): string
{
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function move_account(int $id, string $dir): void
{
  $pdo = db();
  $pdo->beginTransaction();
  $ids = array_map('intval', $pdo->query('SELECT id FROM accounts ORDER BY sort_order, id')->fetchAll(PDO::FETCH_COLUMN));
  $i = array_search($id, $ids, true);
  if ($i !== false) {
    $j = $dir === 'up' ? $i - 1 : $i + 1;
    if (isset($ids[$j])) [$ids[$i], $ids[$j]] = [$ids[$j], $ids[$i]];
  }
  $st = $pdo->prepare('UPDATE accounts SET sort_order = ? WHERE id = ?');
  foreach ($ids as $k => $v) $st->execute([$k, $v]);
  $pdo->commit();
}

$error = '';
$errTarget = '';
$form = ['uri' => '', 'issuer' => '', 'label' => '', 'secret' => ''];
$editForm = ['issuer' => '', 'label' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
  $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
  $bad = ($site !== '' && $site !== 'same-origin' && $site !== 'none')
    || ($origin !== '' && parse_url($origin, PHP_URL_HOST) !== parse_url('//' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST));
  if ($bad) {
    http_response_code(403);
    exit('Forbidden');
  }

  $action = (string)($_POST['action'] ?? '');
  $id = (int)($_POST['id'] ?? 0);
  try {
    if ($action === 'add') {
      $errTarget = 'add';
      $uri = trim((string)($_POST['uri'] ?? ''));
      $acc = normalize_account($uri !== '' ? parse_otpauth($uri) : $_POST);
      totp_code($acc['secret'], $acc['digits'], $acc['period'], $acc['algo'], time());
      db()->prepare('INSERT INTO accounts (issuer, label, secret, digits, period, algo, sort_order) VALUES (?,?,?,?,?,?, (SELECT COALESCE(MAX(m.sort_order), -1) + 1 FROM (SELECT sort_order FROM accounts) AS m))')
        ->execute([$acc['issuer'], $acc['label'], $acc['secret'], $acc['digits'], $acc['period'], $acc['algo']]);
      header('Location: totp.php', true, 303);
      exit;
    }
    if ($action === 'rename') {
      $errTarget = 'edit-' . $id;
      $issuer = mb_substr(trim((string)($_POST['issuer'] ?? '')), 0, 100);
      $label  = mb_substr(trim((string)($_POST['label'] ?? '')), 0, 190);
      if ($issuer === '' && $label === '') throw new InvalidArgumentException('Please enter at least one of service name or account name.');
      db()->prepare('UPDATE accounts SET issuer = ?, label = ? WHERE id = ?')->execute([$issuer, $label, $id]);
      header('Location: totp.php', true, 303);
      exit;
    }
    if ($action === 'move') {
      $dir = (string)($_POST['dir'] ?? '');
      if ($dir === 'up' || $dir === 'down') move_account($id, $dir);
      header('Location: totp.php?open=sort', true, 303);
      exit;
    }
    if ($action === 'delete') {
      db()->prepare('DELETE FROM accounts WHERE id = ?')->execute([$id]);
      header('Location: totp.php', true, 303);
      exit;
    }
  } catch (InvalidArgumentException $e) {
    $error = $e->getMessage();
    foreach ($form as $k => $_) $form[$k] = (string)($_POST[$k] ?? '');
    $editForm = ['issuer' => (string)($_POST['issuer'] ?? ''), 'label' => (string)($_POST['label'] ?? '')];
  }
}
$openTarget = $errTarget !== '' && $error !== '' ? $errTarget : (($_GET['open'] ?? '') === 'sort' ? 'sort' : '');

$rows = db()->query('SELECT id, issuer, label, secret, digits, period, algo FROM accounts ORDER BY sort_order, id')->fetchAll();
$t = microtime(true);
$now = (int)$t;
$refresh = 30;
foreach ($rows as &$r) {
  try {
    $r['code'] = totp_code($r['secret'], (int)$r['digits'], (int)$r['period'], $r['algo'], $now);
  } catch (Throwable $e) {
    $r['code'] = null;
  }
  $period = (int)$r['period'];
  $r['remain'] = $period - ($now % $period);
  $r['elapsed'] = fmod($t, $period);
  $r['title'] = $r['issuer'] !== '' && $r['label'] !== ''
    ? $r['issuer'] . ' / ' . $r['label']
    : ($r['issuer'] !== '' ? $r['issuer'] : $r['label']);
}
unset($r);
if ($rows) $refresh = max(1, min(array_column($rows, 'remain')));
$openAttr = fn(string $id): string => $openTarget === $id ? ' data-open' : '';
?>
<!doctype html>
<html lang="ja">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta name="robots" content="noindex,nofollow">
  <title>TOTP</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2024%2024'%3E%3Cpath%20fill='%230b6e66'%20d='M18%208h-1V6c0-2.76-2.24-5-5-5S7%203.24%207%206v2H6c-1.1%200-2%20.9-2%202v10c0%201.1.9%202%202%202h12c1.1%200%202-.9%202-2V10c0-1.1-.9-2-2-2zm-6%209c-1.1%200-2-.9-2-2s.9-2%202-2%202%20.9%202%202-.9%202-2%202zm3.1-9H8.9V6c0-1.71%201.39-3.1%203.1-3.1%201.71%200%203.1%201.39%203.1%203.1v2z'/%3E%3C/svg%3E">
  <link rel="stylesheet" href="style.css">
  <script src="totp.js" defer></script>
</head>

<body data-refresh="<?= (int)$refresh ?>">
  <main>
    <header>
      <h1>TOTP</h1>
      <div class="actions">
        <?php if (count($rows) >= 2): ?>
          <button type="button" class="quiet" popovertarget="sort">Sort</button>
        <?php endif; ?>
        <button type="button" class="primary" popovertarget="add">Add</button>
      </div>
    </header>

    <?php if (!$rows): ?>
      <p class="note">No accounts found. Please add an account.</p>
    <?php else: ?>
      <ul id="list">
        <?php foreach ($rows as $r):
          $anim = sprintf('animation-duration:%ds;animation-delay:-%.2fs', $r['period'], $r['elapsed']);
          $half = (int)ceil((int)$r['digits'] / 2);
          $shown = $r['code'] === null ? '------' : substr($r['code'], 0, $half) . ' ' . substr($r['code'], $half);
        ?>
          <li class="row">
            <div class="main">
              <span class="name">
                <strong><?= h($r['issuer'] !== '' ? $r['issuer'] : $r['label']) ?></strong>
                <?php if ($r['issuer'] !== '' && $r['label'] !== ''): ?><span><?= h($r['label']) ?></span><?php endif; ?>
              </span>
              <button type="button" class="code" style="<?= $anim ?>" <?= $r['code'] !== null ? ' data-code="' . h($r['code']) . '"' : '' ?> title="Copy on click"><?= h($shown) ?></button>
            </div>
            <div class="tools">
              <button type="button" popovertarget="edit-<?= (int)$r['id'] ?>">Edit</button>
              <button type="button" popovertarget="del-<?= (int)$r['id'] ?>">Delete</button>
            </div>
            <span class="bar"><i style="<?= $anim ?>"></i></span>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </main>

  <div id="toast" role="status" aria-live="polite"></div>

  <div id="add" popover class="dlg" <?= $openAttr('add') ?>>
    <form method="post" action="totp.php">
      <div class="dlg-head">
        <h2>Add Account</h2>
        <button type="button" class="icon" popovertarget="add" popovertargetaction="hide" aria-label="Close">&times;</button>
      </div>
      <div class="dlg-body">
        <input type="hidden" name="action" value="add">

        <label for="add-issuer">Service Name</label>
        <input id="add-issuer" name="issuer" type="text" maxlength="100" autocomplete="off" autofocus value="<?= h($form['issuer']) ?>">
        <label for="add-label">Account Name</label>
        <input id="add-label" name="label" type="text" maxlength="190" autocomplete="off" value="<?= h($form['label']) ?>">
        <label for="add-secret">Secret (Base32)</label>
        <input id="add-secret" name="secret" type="text" spellcheck="false" autocomplete="off" value="<?= h($form['secret']) ?>">

        <details<?= $form['uri'] !== '' ? ' open' : '' ?>>
          <summary>Add from otpauth:// URI</summary>
          <textarea id="add-uri" name="uri" rows="3" spellcheck="false" autocomplete="off"><?= h($form['uri']) ?></textarea>
          <p class="note">If you enter a URI, it will take precedence over the manual input fields above.</p>
        </details>

        <p class="error" role="alert"><?= $errTarget === 'add' ? h($error) : '' ?></p>
      </div>
      <div class="buttons dlg-foot">
        <button type="button" class="quiet" popovertarget="add" popovertargetaction="hide">Cancel</button>
        <button type="submit" class="primary">Add</button>
      </div>
    </form>
  </div>

  <?php if (count($rows) >= 2): ?>
    <div id="sort" popover class="dlg" <?= $openAttr('sort') ?>>
      <div class="dlg-head">
        <h2>Sort</h2>
        <button type="button" class="icon" popovertarget="sort" popovertargetaction="hide" aria-label="Close">&times;</button>
      </div>
      <div class="dlg-body">
        <ul class="sortlist">
          <?php foreach ($rows as $i => $r): ?>
            <li>
              <span class="sortname"><?= h($r['title']) ?></span>
              <form method="post" action="totp.php" class="mv">
                <input type="hidden" name="action" value="move">
                <input type="hidden" name="id" value="<?= (int)$r['id'] ?>">
                <button type="submit" name="dir" value="up" aria-label="Up" title="Up" <?= $i === 0 ? ' disabled' : '' ?>>&uarr;</button>
                <button type="submit" name="dir" value="down" aria-label="Down" title="Down" <?= $i === count($rows) - 1 ? ' disabled' : '' ?>>&darr;</button>
              </form>
            </li>
          <?php endforeach; ?>
        </ul>
      </div>
      <div class="buttons dlg-foot">
        <button type="button" class="primary" popovertarget="sort" popovertargetaction="hide">Close</button>
      </div>
    </div>
  <?php endif; ?>

  <?php foreach ($rows as $r):
    $id = (int)$r['id'];
    $editing = $errTarget === 'edit-' . $id && $error !== '';
    $vIssuer = $editing ? $editForm['issuer'] : $r['issuer'];
    $vLabel  = $editing ? $editForm['label'] : $r['label'];
  ?>
    <div id="edit-<?= $id ?>" popover class="dlg" <?= $openAttr('edit-' . $id) ?>>
      <form method="post" action="totp.php">
        <div class="dlg-head">
          <h2>Change Name</h2>
          <button type="button" class="icon" popovertarget="edit-<?= $id ?>" popovertargetaction="hide" aria-label="Close">&times;</button>
        </div>
        <div class="dlg-body">
          <input type="hidden" name="action" value="rename">
          <input type="hidden" name="id" value="<?= $id ?>">
          <label for="edit-issuer-<?= $id ?>">Service Name</label>
          <input id="edit-issuer-<?= $id ?>" name="issuer" type="text" maxlength="100" autocomplete="off" value="<?= h($vIssuer) ?>">
          <label for="edit-label-<?= $id ?>">Account Name</label>
          <input id="edit-label-<?= $id ?>" name="label" type="text" maxlength="190" autocomplete="off" value="<?= h($vLabel) ?>">
          <p class="error" role="alert"><?= $editing ? h($error) : '' ?></p>
        </div>
        <div class="buttons dlg-foot">
          <button type="button" class="quiet" popovertarget="edit-<?= $id ?>" popovertargetaction="hide">Cancel</button>
          <button type="submit" class="primary">Save</button>
        </div>
      </form>
    </div>

    <div id="del-<?= $id ?>" popover class="dlg warn">
      <form method="post" action="totp.php">
        <div class="dlg-head">
          <h2>Confirm Deletion</h2>
          <button type="button" class="icon" popovertarget="del-<?= $id ?>" popovertargetaction="hide" aria-label="Close">&times;</button>
        </div>
        <div class="dlg-body">
          <p>Are you sure you want to delete "<strong><?= h($r['title']) ?></strong>"?</p>
          <p class="note">Once deleted, this code will not be displayed again. Please remove 2FA from the service before deleting.</p>
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="id" value="<?= $id ?>">
        </div>
        <div class="buttons dlg-foot">
          <button type="button" class="quiet" popovertarget="del-<?= $id ?>" popovertargetaction="hide">Cancel</button>
          <button type="submit" class="danger">Delete</button>
        </div>
      </form>
    </div>
  <?php endforeach; ?>
</body>

</html>