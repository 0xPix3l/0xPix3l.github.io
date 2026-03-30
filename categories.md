---
layout: page
title: Categories
permalink: /categories/
---

<div class="taxonomy-list">
{% for category in site.categories %}
<div class="taxonomy-group" id="{{ category[0] | slugify }}">
  <h2 class="taxonomy-title">
    <span class="taxonomy-name">{{ category[0] }}</span>
    <span class="taxonomy-count">{{ category[1].size }}</span>
  </h2>
  <ul class="taxonomy-posts">
    {% for post in category[1] %}
    <li>
      <span class="archive-date">{{ post.date | date: "%b %d, %Y" }}</span>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    </li>
    {% endfor %}
  </ul>
</div>
{% endfor %}
</div>
