PSYNC - Partial/Full Sync Library based on BF and IBF
=====================================================

PSync is a C++ library for name synchronization that implements the `PSync protocol
<https://named-data.net/wp-content/uploads/2017/05/scalable_name-based_data_synchronization.pdf>`__.
It uses Invertible Bloom Lookup Table (IBLT), also known as Invertible Bloom Filter (IBF),
to represent the state of a producer in partial sync mode and the state of a node in full
sync mode. An IBF is a compact data structure where difference of two IBFs can be computed
efficiently. In partial sync, PSync uses a Bloom Filter to represent the subscription of
list of the consumer.

PSync uses the `ndn-cxx <https://github.com/named-data/ndn-cxx>`__ library.

Contributing
------------

We greatly appreciate contributions to the PSync code base, provided that they are
licensed under the LGPL 3.0+ or a compatible license (see `COPYING.md
<https://github.com/named-data/PSync/blob/master/COPYING.md>`__ for more information).
If you are new to the NDN software community, please read the `Contributor's Guide
<https://github.com/named-data/.github/blob/master/CONTRIBUTING.md>`__ to get started.

Please submit any bug reports or feature requests to the `PSync issue tracker
<https://redmine.named-data.net/projects/psync/issues>`__.

PSync Documentation
-------------------

.. toctree::
   :hidden:
   :maxdepth: 2

   install
   examples
   RELEASE-NOTES
   releases

-  :doc:`install`
-  :doc:`examples`
-  :doc:`RELEASE-NOTES`
-  :doc:`releases`
