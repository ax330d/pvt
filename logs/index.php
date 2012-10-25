<?php

echo <<<HTML
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <title>PVT</title>
        <link rel='stylesheet' type='text/css' href='./design/index.css'>
        <!--<script src="./include/main.js"></script>-->
    </head>

    <body>

        <div id="top">
            <h2>PHP Vulnerability Tracer</h2>
        </div>

        <div id="menu">
            <a href="./dump/opcodes">View opcodes</a>&nbsp;
            <a href="./dump/">View variables trace</a>&nbsp;

            <a href="./dump/">View functions trace</a>&nbsp;
            <a href="./dump/">View functions trace 2</a>&nbsp;
        </div>

        <div id="butt">

            <p>
                This browser session hash: <span id="sess_hash"></span>
            </p>

            <span id="warn"></span>

        </div>

        <div class="boxy" style="clear:both;">
        </div>
    </body>

</html>
HTML;
