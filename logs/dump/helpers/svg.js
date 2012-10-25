/**
 * PVT - PHP Vulnerability Tracer
 * JavaScript functions for graph manipulation
 */

var color_on   = 'red';
var color_off  = 'black'
var color_self = 'yellow';
var logMode = parent.logMode;

_POST   = parent._POST;
makeBox = parent.makeBox;

/* Highlight clicked line */
function cs(t) {

    if (t.childNodes[1].getAttribute('stroke') == color_on) {
        t.childNodes[1].setAttribute('stroke', color_off);
        t.childNodes[3].setAttribute('stroke', color_off);
        t.childNodes[3].setAttribute('fill', color_off);
    } else {
        t.childNodes[1].setAttribute('stroke', color_on);
        t.childNodes[3].setAttribute('stroke', color_on);
        t.childNodes[3].setAttribute('fill', color_on);
    }
}

function ce(t) {

}

function cd(t) {
    
}

/* Load some file */
function cl(obj, line) {
    
    var aObj = obj.parentNode.childNodes[5];
    var ary = aObj.attributes[0].nodeValue.split(':');
    
    var obj = makeBox(ary[0], line);

    _POST('../dump/helpers/get.php', 'file=' + ary[0] + '&line=' + line + '&mode=' + logMode, obj);
    
}

function highlightFunction(obj) {
    if (obj.getAttribute('fill') == color_on) {
        obj.setAttribute('fill', color_off);
    } else {
        obj.setAttribute('fill', color_on);
    }
}

/* Get related ID by clicking on text (function name) */
function cb(t) {
    
    var cl = t.getAttribute('class');
    var items = document.getElementsByTagName('a');
    for (var i = 0; i < items.length; i++) {
        if (items[i].getAttribute('class') == cl) {
            cs(items[i]);
        }
    }

    var items = document.getElementsByTagName('text');
    for (var i = 0; i < items.length; i++) {
        if (items[i].getAttribute('class') == cl) {
            highlightFunction(items[i]);    
        }
    }

}
