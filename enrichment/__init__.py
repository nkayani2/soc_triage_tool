"""Enrichment subpackage for the SOC Triage Tool.

Each enricher is a small, self-contained class that queries a single
external API and returns a normalized dictionary.  New enrichers can be
added by subclassing :class:`base.BaseEnricher`.
"""
