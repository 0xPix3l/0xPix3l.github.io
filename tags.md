---
layout: page
title: Tags
permalink: /tags/
---

<div class="tags-cloud">
{% for tag in site.tags %}
  <a href="#{{ tag[0] | slugify }}" class="tag-cloud-item">{{ tag[0] }} <sup>{{ tag[1].size }}</sup></a>
{% endfor %}
</div>

<div class="taxonomy-list">
{% for tag in site.tags %}
<div class="taxonomy-group" id="{{ tag[0] | slugify }}">
  <h2 class="taxonomy-title">
    <span class="taxonomy-name">#{{ tag[0] }}</span>
    <span class="taxonomy-count">{{ tag[1].size }}</span>
  </h2>
  <ul class="taxonomy-posts">
    {% for post in tag[1] %}
    <li>
      <span class="archive-date">{{ post.date | date: "%b %d, %Y" }}</span>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    </li>
    {% endfor %}
  </ul>
</div>
{% endfor %}
</div>
