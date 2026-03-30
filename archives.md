---
layout: page
title: Archives
permalink: /archives/
---

<div class="archive-list">
{% assign postsByYear = site.posts | group_by_exp: "post", "post.date | date: '%Y'" %}
{% for year in postsByYear %}
<div class="archive-year">
  <h2 class="archive-year-title">{{ year.name }}</h2>
  <ul class="archive-posts">
    {% for post in year.items %}
    <li class="archive-item">
      <span class="archive-date">{{ post.date | date: "%b %d" }}</span>
      <a href="{{ post.url | relative_url }}" class="archive-link">{{ post.title }}</a>
      {% if post.categories.size > 0 %}
        <span class="archive-cat">{{ post.categories | first }}</span>
      {% endif %}
    </li>
    {% endfor %}
  </ul>
</div>
{% endfor %}
</div>
