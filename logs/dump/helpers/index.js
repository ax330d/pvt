/**
 * PVT - PHP Vulnerability Tracer
 * JavaScript functions for graph manipulation
 */
var memPrev     = null;
var heightPrev  = null;
var nextFile    = 0;
var path        = '';
var logMode     = 'a';
var boxNum      = 1;

function startG(fileName) {

    logMode = getLogMode();

    if (!fileName) fileName = 'graph0';
    path = "./pvt-common-" + logMode + "/" + fileName + ".svg";
    var obj = document.getElementById('run');
    obj.innerHTML = '<object data="' + path + '" id="graph"/><p style="color:red">Not loaded: ' + path + '</p></object>';

    changeHref();
}

function getLogMode() {
    if (localStorage.getItem('modeG') == 'a') {
        return 'a';
    } else if (localStorage.getItem('modeG') == 'w') {
        return 'w';
    } else {
        return 'a';
    }
}

function changeHref() {
    var h = window.location.href.split('#');
    h[1] = 'Loaded file: ' + path + ', zoom: ' + parseFloat(scaleNum * 100) + '%';
    window.location.href = h.join('#');
}

function nextG() {
    nextFile += 1;
    startG('graph' + nextFile);
}

function prevG() {
    nextFile -= 1;
    startG('graph' + nextFile);
}

function cm(fileAndLine) {
    var ary = fileAndLine.split(':');
    var obj = makeBox(ary[0], ary[1]);
    logMode = getLogMode();
    _POST('../dump/helpers/get.php', 'file=' + ary[0] + '&line=' + ary[1] + '&mode=' + logMode /*+ '#t_' + ary[1]*/, obj);
}

var scaleNum = 1;
function scaleP() {
    var obj = document.getElementById('graph').contentDocument;
    var inObj = obj.getElementById('graph1');
    var prevScale = inObj.getAttribute('transform');
    var atrs = prevScale.split(')');
    scaleNum += 0.1;
    var s = 'scale(' + scaleNum + ' ' + scaleNum + ') ' + atrs[1] + ') ' + atrs[2] + ')';
    inObj.setAttribute('transform', s);
    
    changeHref();
}

function scaleM() {
    var obj = document.getElementById('graph').contentDocument;
    var inObj = obj.getElementById('graph1');
    var prevScale = inObj.getAttribute('transform');
    var atrs = prevScale.split(')');
    scaleNum -= 0.1;
    var s = 'scale(' + scaleNum + ' ' + scaleNum + ') ' + atrs[1] + ') ' + atrs[2] + ')';
    inObj.setAttribute('transform', s);
    
    changeHref();
}

function modeG(mtype) {
    localStorage.setItem('modeG', mtype);
    startG();
}

function mem(obj) {
    if (obj.className == 'memLine') {
        obj.className = memPrev;
    } else {
        memPrev = obj.className;
        obj.className = 'memLine';
    }
}

function closeme(which) {
    var elem = document.getElementById(which);
    elem.parentNode.removeChild(elem);
}

function makeBox(path, line) {
    boxNum += 1;
    var title = path + ':' + line;
    var short_title = title.split('/').pop();
    var html = "\
<div class=\"body\" id=\"body_" + boxNum + "\" onmousedown=\"dragStart(event, 'box', " + boxNum + ");\">\
    <div class=\"header\" id=\"header_" + boxNum + "\">\
        <span class=\"title\" id=\"title_" + boxNum + "\" \
            onmouseout=\"tooltipRemove()\" \
            onmouseover=\"tooltipShow('" + title + "')\">.../" + short_title + "</span>\
        <span class=\"closeme\" onclick=\"closeme('box_" + boxNum + "');\">Close</span>\
        <div style=\"clear: both\"></div>\
    </div>\
</div>\
<div class=\"content\" id=\"content_" + boxNum + "\"></div>";
    
    var tooltip = document.createElement('div');
    tooltip.id = 'box_' + boxNum;
    tooltip.className  = 'box';
    tooltip.style.top  = '40px';
    tooltip.style.left = '40px';
    document.body.appendChild(tooltip);

    document.getElementById('box_' + boxNum).innerHTML = html;
    var obj = document.getElementById('content_' + boxNum);
    obj.style.height = '200px';
    obj.style.width  = '300px';
    
    return obj;
}

var l = 0, t = 0;
var IE = document.all ? true : false;
document.onmousemove = getMouseXY;
var tooltip = document.createElement('div');

function getMouseXY(e) {
    if (IE) {
        l = event.clientX + document.body.scrollLeft;
        t = event.clientY + document.body.scrollTop;
    } else {
        l = e.pageX;
        t = e.pageY;
    }  
    tooltip.style.left = l + 'px';
    tooltip.style.top = t + 'px';
    return true;
}

/* Creates tooltip */
function tooltipShow(text) {
    document.body.appendChild(tooltip);
    tooltip.id = 'tooltip';
    tooltip.innerHTML = text;
}

function tooltipRemove() {
    if (document.getElementById('tooltip')) {
        document.body.removeChild(document.getElementById('tooltip'));
    }
}

//*****************************************************************************
// Do not remove this notice.
//
// Copyright 2001 by Mike Hall.
// See http://www.brainjar.com for terms of use.
//*****************************************************************************

// Determine browser and version.

function Browser() {

    var ua, s, i;

    this.isIE    = false;
    this.isNS    = false;
    this.version = null;

    ua = navigator.userAgent;

    s = "MSIE";
    if ((i = ua.indexOf(s)) >= 0) {
        this.isIE = true;
        this.version = parseFloat(ua.substr(i + s.length));
        return;
    }

    s = "Netscape6/";
    if ((i = ua.indexOf(s)) >= 0) {
        this.isNS = true;
        this.version = parseFloat(ua.substr(i + s.length));
        return;
    }

    // Treat any other "Gecko" browser as NS 6.1.

    s = "Gecko";
    if ((i = ua.indexOf(s)) >= 0) {
        this.isNS = true;
        this.version = 6.1;
        return;
    }
    }

var browser = new Browser();

// Global object to hold drag information.

var dragObj = new Object();
dragObj.zIndex = 0;

function dragStart(event, id, boxNum) {
    id = id + "_" + boxNum;
    var el;
    var x, y;

    // If an element id was given, find it. Otherwise use the element being
    // clicked on.

    if (id)
        dragObj.elNode = document.getElementById(id);
    else {
        if (browser.isIE)
        dragObj.elNode = window.event.srcElement;
        if (browser.isNS)
        dragObj.elNode = event.target;

        // If this is a text node, use its parent element.

        if (dragObj.elNode.nodeType == 3)
        dragObj.elNode = dragObj.elNode.parentNode;
    }

    // Get cursor position with respect to the page.

    if (browser.isIE) {
        x = window.event.clientX + document.documentElement.scrollLeft
        + document.body.scrollLeft;
        y = window.event.clientY + document.documentElement.scrollTop
        + document.body.scrollTop;
    }
    if (browser.isNS) {
        x = event.clientX + window.scrollX;
        y = event.clientY + window.scrollY;
    }

    // Save starting positions of cursor and element.

    dragObj.cursorStartX = x;
    dragObj.cursorStartY = y;
    dragObj.elStartLeft  = parseInt(dragObj.elNode.style.left, 10);
    dragObj.elStartTop   = parseInt(dragObj.elNode.style.top,  10);

    if (isNaN(dragObj.elStartLeft)) dragObj.elStartLeft = 0;
    if (isNaN(dragObj.elStartTop))  dragObj.elStartTop  = 0;

    // Update element's z-index.

    dragObj.elNode.style.zIndex = ++dragObj.zIndex;

    // Capture mousemove and mouseup events on the page.

    if (browser.isIE) {
        document.attachEvent("onmousemove", dragGo);
        document.attachEvent("onmouseup",   dragStop);
        window.event.cancelBubble = true;
        window.event.returnValue = false;
    }
    if (browser.isNS) {
        document.addEventListener("mousemove", dragGo,   true);
        document.addEventListener("mouseup",   dragStop, true);
        event.preventDefault();
    }
    hiddden = document.getElementById('content_' + boxNum);
    heightPrev = hiddden.style.height;
    hiddden.style.height = '10px';
    window.document.hidden = hiddden;
    dragObj.elNode.style.opacity = '.50';

}

function dragGo(event) {

    var x, y;

    // Get cursor position with respect to the page.

    if (browser.isIE) {
        x = window.event.clientX + document.documentElement.scrollLeft
        + document.body.scrollLeft;
        y = window.event.clientY + document.documentElement.scrollTop
        + document.body.scrollTop;
    }
    if (browser.isNS) {
        x = event.clientX + window.scrollX;
        y = event.clientY + window.scrollY;
    }

    // Move drag element by the same amount the cursor has moved.

    dragObj.elNode.style.left = (dragObj.elStartLeft + x - dragObj.cursorStartX) + "px";
    dragObj.elNode.style.top  = (dragObj.elStartTop  + y - dragObj.cursorStartY) + "px";

    if (browser.isIE) {
        window.event.cancelBubble = true;
        window.event.returnValue = false;
    }
    if (browser.isNS)
        event.preventDefault();

    dragObj.elNode.style.cursor = 'move';
}

function dragStop(event) {

  // Stop capturing mousemove and mouseup events.
    dragObj.elNode.style.opacity = '1.0';
    dragObj.elNode.style.cursor = 'auto';

    window.document.hidden.style.height = heightPrev;

    if (browser.isIE) {
        document.detachEvent("onmousemove", dragGo);
        document.detachEvent("onmouseup",   dragStop);
    }
    if (browser.isNS) {
        document.removeEventListener("mousemove", dragGo,   true);
        document.removeEventListener("mouseup",   dragStop, true);
    }
}

var http_request = false;
function _POST(url, parameters, obj) {
    obj.innerHTML = '<span class="al"> Loading...</span>'
    http_request = false;
    
    if (window.XMLHttpRequest) {
        http_request = new XMLHttpRequest();
        if (http_request.overrideMimeType) http_request.overrideMimeType('text/html');
    } else if (window.ActiveXObject) {
        try {
            http_request = new ActiveXObject("Msxml2.XMLHTTP");
        } catch (e) {
            try {
                http_request = new ActiveXObject("Microsoft.XMLHTTP");
            } catch (e) {}
        }
    }
    
    if (!http_request) {
        alert('Cannot create XMLHTTP instance');
        return false;
    }
    
    http_request.onreadystatechange = function() {
        if (http_request.readyState == 4 ||  (http_request.readyState == 3)) {    
            if (http_request.status == 200) {
                obj.innerHTML = http_request.responseText;
                var a = document.getElementById('t_' + 100);//alert(a)
                if (a) a.scrollTop = a.offsetTop;

            } else {
            }
        }
    }
    try {
        http_request.open('POST', url, true);
        http_request.setRequestHeader("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
        http_request.setRequestHeader("Cache-Control", "no-cache, must-revalidate, post-check=0, pre-check=0");  
        http_request.send(parameters);
    } catch(e) {
        alert(e);
    }
}