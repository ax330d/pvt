<?php
/**
 * PVT source code browser
 */
/*
$_POST['mode']='a';
$_POST['line']='48';
$_POST['file']='/var/www/htdocs/pma/libraries/navigation_header.inc.php';
*/
error_reporting(E_ALL);

$mapf = '';
$mode = '';

/* Try to include file of function mappings */
if (isset($_POST['mode']))
    $mode = $_POST['mode'];
if ($mode == 'a') {
    $mapf = '../pvt-common-a/mapped-funcs.php';
} else if ($mode == 'w') {
    $mapf = '../pvt-common-w/mapped-funcs.php';
}

if (file_exists($mapf)) {
    include($mapf);
} else {
    echo($mapf . $mode);
}

/* I need some variables, om nom nom */
if (isset($_POST['file'])) {
    $file = $_POST['file'];
}
if (isset($_POST['line'])) {
    $line = (int)$_POST['line'];
}
if (!file_exists($file)) {
    die("No such file: $file!");
}

/* Functions for potential RCE */
$sec_funcs_1 = implode('|', array(
    'eval', 'create_function', 'preg_replace', 'call_user_func', 'assert', 'ob_start',
    'call_user_func_array', 'call_user_method',
    'extract', 'parse_str', 'import_request_variables', 
    'shell_exec', 'system', 'exec', 'passthru', 'popen', 'proc_open', 
    'unserialize'
));

/* Less possible functions for RCE */
$sec_funcs_2 = implode('|', array(
    'array_filter', 'array_map', 'array_reduce', 'uasort', 'uksort', 'array_walk',
    'array_udiff_uassoc', 'array_udiff_assoc', 'array_diff_uassoc', 'array_diff_ukey', 
    'array_udiff', 'preg_replace_callback', 
    'stream_filter_register', 'create_function', 
    'call_user_method_array', 'stream_socket_server'
));

/* File system operations */
$sec_funcs_3 = implode('|', array(
    'file', 'fopen', 'file_get_contents', 'readfile', 'curl_exec', 
    'move_uploaded_file',
    'chmod', 'unlink',
    'include', 'include_once', 'require', 'require_once',
    'file_put_contents', 'show_source', 'highlight_file'
));

/* constructs */
$funcs = implode('|', array(
    'return', 'elseif',
    'else', 'if', 'switch', 'case', 'default',
    'while', 'for', 'foreach',
    'isset', 'try', 'catch',
    'echo', 'print', 'print_r'
));

$pregFrom = array(
    '/(\'(?:.*?)\')/is',
    '/(\$[a-zA-Z_\x7f-\xff][a-z0-9_\x7f-\xff]*)/i',
    '/(\$_(?:POST|GET|REQUEST|COOKIE|FILES|SERVER))/i',
    "/((?:$funcs)(?:\s+|\())/",
    "/((?:$sec_funcs_1)(?:\s+|\())/",
    "/((?:$sec_funcs_2)(?:\s+|\())/",
    "/((?:$sec_funcs_3)(?:\s+|\())/"
);
$pregTo = array(
    "<span class=\"text\">\\1</span>",
    "<span class=\"vars\">\\1</span>",
    "<span class=\"boldg\">\\1</span>",
    "<span class=\"bold\">\\1</span>",
    "<span class=\"secf1\">\\1</span>",
    "<span class=\"secf2\">\\1</span>",
    "<span class=\"secf3\">\\1</span>"
);

$str = '<table><tr><td></td><td></td><td></td></tr>';
$string = file_get_contents($file);

$string = htmlspecialchars($string);
$string = preg_replace($pregFrom, $pregTo, $string);
$ary = explode("\n", $string);

$start_comment = FALSE;
$start_string = FALSE;
$i = 0;
foreach ($ary as $code) {
    $i++; $cl = '';
    if ($i == $line) {
        $cl = ' class="hl"';
    }
    $def_func = FALSE;
    /* Try to find strings */
    $string_two = strpos($code, '"');
    $string_one = strpos($code, '\'');
    $string_phps = strpos($code, '?>');
    $string_phpe = strpos($code, '<?php');

    if ($string_two !== FALSE) {
        
    }

    $comm_ol    = strpos($code, '//');
    $comm_start = strpos($code, '/*');
    $comm_end   = strpos($code, '*/');

    /* If multilitine comment is on one line */
    if ($comm_end !== FALSE && $comm_start !== FALSE) {
        $code = substr_replace($code, '</span>', $comm_end + 2, 0);
        $code = substr_replace($code, '<span class="comm">', $comm_start, 0);
    }
    if ($comm_start !== FALSE && $comm_end === FALSE) {
        $start_comment = TRUE;
    }
    if ($start_comment == TRUE) {
        $cl = ' class="comm"';
        $code = preg_replace('/<span\s+class=\"(?:.*?)\">/', '', $code);
        $code = preg_replace('/<\/span>/', '', $code);
    }
    if ($comm_ol !== FALSE) {
        $code = preg_replace('/<span\s+class=\"(?:.*?)\">/', '', $code);
        $code = preg_replace('/<\/span>/', '', $code);
        $code = substr_replace($code, '<span class="comm">', $comm_ol, 0);
        $code .= '</span>';
    }

    
    if (preg_match("/((?:function)(?:\s+|\())/", $code, $out)) {
        $def_func = TRUE;
    }

    if ($mapf != '' && $start_comment === FALSE && $comm_ol === FALSE && !$def_func) {
        if (preg_match_all('/(?:([a-zA-Z_\x7f-\xff][a-z0-9_\x7f-\xff]*(?:|(?:->|::)[a-zA-Z_\x7f-\xff][a-z0-9_\x7f-\xff]*))(?:\(|\s+\())/is', $code, $out)) {
            foreach ($out[1] as $k => $v) {
                if (array_key_exists($v, $mapped_funcs)) {
                    $path = $mapped_funcs[ $v ];
                    $code = strtr($code, array($v => "<a class=\"mapf\" onclick=\"cm('$path'); return false;\">{$v}</a>"));
                }
            }
        }
    }

    $str .= "<tr$cl ondblclick=\"mem(this)\"><td class=\"f\">$i</td><td><pre>$code</pre></td><td><a id=\"t_$i\" href=\"#t_$i\"> </a></td></tr>\n";
    if ($comm_end !== FALSE) {
        $start_comment = FALSE;
    }
}

$str .= '</table>';
echo $str;
