<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path === '/health') {
    echo json_encode(['ok' => true, 'php' => PHP_VERSION, 'sapi' => PHP_SAPI,
        'debug' => (bool) PHP_DEBUG, 'zts' => (bool) PHP_ZTS,
        'allocator_env' => ['USE_ZEND_ALLOC' => getenv('USE_ZEND_ALLOC'),
                            'USE_TRACKED_ALLOC' => getenv('USE_TRACKED_ALLOC')],
        'upload_progress' => ini_get('session.upload_progress.enabled'),
        'serializer' => ini_get('session.serialize_handler')]);
} elseif ($path === '/upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $file = $_FILES['file'] ?? null;
    if (!$file || $file['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode(['ok' => false]);
        exit;
    }
    echo json_encode(['ok' => true, 'size' => $file['size'],
        'sha256' => hash_file('sha256', $file['tmp_name'])]);
} elseif ($path === '/session') {
    session_start();
    $_SESSION['visits'] = ($_SESSION['visits'] ?? 0) + 1;
    echo json_encode(['ok' => true, 'visits' => $_SESSION['visits']]);
    session_write_close();
} elseif ($path === '/unserialize' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // Lab-only producer endpoint for CVE-2026-109619 Path C: a runtime
    // (post-RINIT) unserialize of request data. Memory errors are observed
    // by the harness; nothing here grooms or controls memory.
    $raw = file_get_contents('php://input');
    $value = unserialize($raw);
    echo json_encode(['ok' => true, 'type' => gettype($value)]);
} else {
    http_response_code(404);
    echo json_encode(['ok' => false, 'error' => 'not found']);
}
