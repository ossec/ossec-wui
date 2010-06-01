// Java script to hide/show parts of the site.

function HideSection(p)
{
    t = ('toggle' + (p));
    n = ('content' + (p));
    document.getElementById(t).style.display = "block";
    document.getElementById(n).style.display = "none";
}

function ShowSection(p)
{
    t = ('toggle' + (p));
    n = ('content' + (p));
    document.getElementById(t).style.display = "none";
    document.getElementById(n).style.display = "block";
}


// Java script to hide specific levels from the search.

function HideLevelSection(p, q)
{
    t = ('toggle' + (p));
    n = ('ct' + (p));
    document.getElementById(t).style.display = "block";
    document.getElementById(n).style.display = "none";

    for(i = 1; i <= q; i++)
    {
        nn = ('ct' + (p) + '-' +(i));
        document.getElementById(nn).style.display = "none";
    }
}

function ShowLevelSection(p, q)
{
    t = ('toggle' + (p));
    n = ('ct' + (p));
    document.getElementById(t).style.display = "none";
    document.getElementById(n).style.display = "block";

    for(i = 1; i <= q; i++)
    {
        nn = ('ct' + (p) + '-' +(i));
        document.getElementById(nn).style.display = "block";
    }
}

